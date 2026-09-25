use async_trait::async_trait;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use secrets_core::auth::{AuthError, AuthMethod, AuthOutcome, AuthResult, LoginRequest};
use secrets_core::storage::{StorageBackend, StorageEntry};
use serde::{Deserialize, Serialize};

const USER_PREFIX: &str = "auth/userpass/users/";
const DEFAULT_TTL_SECONDS: i64 = 3600;

/// Longest username accepted by [`UserPassAuth::upsert_user`].
pub const MAX_USERNAME_LEN: usize = 64;
/// Shortest password accepted by [`UserPassAuth::upsert_user`], in characters.
/// These identities belong to services, whose passwords are generated, so
/// the floor costs nothing and rules out a guessable one slipping in.
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    password_hash: String,
    policies: Vec<String>,
}

/// What may be said about a user to anyone allowed to manage it. A separate
/// type from the stored record, so the password hash cannot end up in a
/// response by someone serializing the wrong struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub policies: Vec<String>,
}

pub struct UserPassAuth;

impl Default for UserPassAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl UserPassAuth {
    pub fn new() -> Self {
        Self
    }

    pub fn hash_password(password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AuthError::Other(e.to_string()))
    }

    pub async fn user_exists(storage: &dyn StorageBackend, username: &str) -> AuthResult<bool> {
        Ok(storage.get(&user_key(username)).await?.is_some())
    }

    /// Writes a user without validating anything, overwriting any existing
    /// record. This is the bootstrap path: its credentials come from operator
    /// configuration, which predates the HTTP rules and may not meet them
    /// (a short password, an email-shaped name), and refusing them would stop
    /// an existing deployment from starting. Everything reachable over HTTP
    /// goes through [`Self::upsert_user`] instead.
    pub async fn create_user(
        storage: &dyn StorageBackend,
        username: &str,
        password: &str,
        policies: Vec<String>,
    ) -> AuthResult<()> {
        put_user(storage, username, password, policies).await
    }

    /// Creates the user, or replaces it outright: the password is re-hashed
    /// under a fresh salt and the policy list is swapped, not merged, so the
    /// caller always knows exactly what the identity can do afterwards.
    ///
    /// Tokens already issued keep the policies they were minted with until
    /// they expire — a replace narrows future logins, not live sessions.
    pub async fn upsert_user(
        storage: &dyn StorageBackend,
        username: &str,
        password: &str,
        policies: Vec<String>,
    ) -> AuthResult<()> {
        validate_username(username)?;
        validate_password(password)?;
        validate_policies(&policies)?;
        put_user(storage, username, password, policies).await
    }

    /// Makes the user exist with exactly this password and these policies,
    /// under the same rules as [`Self::upsert_user`], and reports whether it
    /// had to write anything.
    ///
    /// This is the declarative path — configuration applied on every start —
    /// so it leaves a user that already matches untouched rather than
    /// re-hashing under a fresh salt each time: a restart is then a no-op,
    /// and a changed password or policy list takes effect on the next one.
    pub async fn ensure_user(
        storage: &dyn StorageBackend,
        username: &str,
        password: &str,
        policies: Vec<String>,
    ) -> AuthResult<bool> {
        validate_username(username)?;
        validate_password(password)?;
        validate_policies(&policies)?;
        if let Some(record) = get_record(storage, username).await?
            && record.policies == policies
            && verify(&record.password_hash, password)?
        {
            return Ok(false);
        }
        put_user(storage, username, password, policies).await?;
        Ok(true)
    }

    /// The user's name and policies, or `None` if there is no such user.
    /// Never the hash: nothing outside `login` has any use for it.
    pub async fn read_user(
        storage: &dyn StorageBackend,
        username: &str,
    ) -> AuthResult<Option<UserInfo>> {
        let Some(record) = get_record(storage, username).await? else {
            return Ok(None);
        };
        Ok(Some(UserInfo {
            username: username.to_string(),
            policies: record.policies,
        }))
    }

    /// Deletes the user, returning whether it existed. Tokens it already
    /// holds are not revoked — they are not indexed by owner — so they keep
    /// working until they expire, and a holder that renews them keeps them
    /// alive.
    pub async fn delete_user(storage: &dyn StorageBackend, username: &str) -> AuthResult<bool> {
        let key = user_key(username);
        if storage.get(&key).await?.is_none() {
            return Ok(false);
        }
        storage.delete(&key).await?;
        Ok(true)
    }
}

/// `[A-Za-z0-9_.-]`, 1 to [`MAX_USERNAME_LEN`] characters, not starting with
/// `.`. The name becomes a storage key and a policy path segment, so it must
/// not carry `/` (which would reach into another key's namespace) or look
/// like a relative path component.
pub fn validate_username(username: &str) -> AuthResult<()> {
    if username.is_empty() || username.len() > MAX_USERNAME_LEN {
        return Err(AuthError::InvalidRequest(format!(
            "username must be 1 to {MAX_USERNAME_LEN} characters"
        )));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(AuthError::InvalidRequest(
            "username may only contain letters, digits, '_', '.' and '-'".into(),
        ));
    }
    if username.starts_with('.') {
        return Err(AuthError::InvalidRequest(
            "username must not start with '.'".into(),
        ));
    }
    Ok(())
}

/// At least [`MIN_PASSWORD_LEN`] characters — counted as characters, not
/// bytes, so a non-ASCII password is not credited for its encoding.
pub fn validate_password(password: &str) -> AuthResult<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthError::InvalidRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// An empty list is fine (an identity that can log in and do nothing); an
/// empty name is not, since it can only be a mistake in the caller.
pub fn validate_policies(policies: &[String]) -> AuthResult<()> {
    if policies.iter().any(|p| p.is_empty()) {
        return Err(AuthError::InvalidRequest(
            "policy names must be non-empty".into(),
        ));
    }
    Ok(())
}

/// Whether `password` matches the stored Argon2 hash. A hash that does not
/// parse is an error, not a mismatch: it means the record is corrupt.
fn verify(password_hash: &str, password: &str) -> AuthResult<bool> {
    let hash = PasswordHash::new(password_hash).map_err(|e| AuthError::Other(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok())
}

fn user_key(username: &str) -> String {
    format!("{USER_PREFIX}{username}")
}

async fn put_user(
    storage: &dyn StorageBackend,
    username: &str,
    password: &str,
    policies: Vec<String>,
) -> AuthResult<()> {
    let record = UserRecord {
        password_hash: UserPassAuth::hash_password(password)?,
        policies,
    };
    let value = serde_json::to_vec(&record).map_err(|e| AuthError::Other(e.to_string()))?;
    storage
        .put(
            &user_key(username),
            StorageEntry {
                value,
                expires_at: None,
            },
        )
        .await?;
    Ok(())
}

async fn get_record(storage: &dyn StorageBackend, username: &str) -> AuthResult<Option<UserRecord>> {
    let Some(entry) = storage.get(&user_key(username)).await? else {
        return Ok(None);
    };
    let record = serde_json::from_slice(&entry.value).map_err(|e| AuthError::Other(e.to_string()))?;
    Ok(Some(record))
}

#[async_trait]
impl AuthMethod for UserPassAuth {
    async fn login(
        &self,
        storage: &dyn StorageBackend,
        request: LoginRequest,
    ) -> AuthResult<AuthOutcome> {
        let LoginRequest::UserPass { username, password } = request else {
            return Err(AuthError::InvalidRequest(
                "expected username/password".into(),
            ));
        };

        let record = get_record(storage, &username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify(&record.password_hash, &password)? {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(AuthOutcome {
            policies: record.policies,
            display_name: username,
            ttl_seconds: Some(DEFAULT_TTL_SECONDS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::storage::StorageResult;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStorage(Mutex<HashMap<String, StorageEntry>>);

    #[async_trait]
    impl StorageBackend for MemStorage {
        async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
            Ok(self.0.lock().unwrap().get(path).cloned())
        }
        async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
            self.0.lock().unwrap().insert(path.to_string(), entry);
            Ok(())
        }
        async fn delete(&self, path: &str) -> StorageResult<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    const PASSWORD: &str = "correct horse battery";

    async fn login(storage: &MemStorage, username: &str, password: &str) -> AuthResult<AuthOutcome> {
        UserPassAuth::new()
            .login(
                storage,
                LoginRequest::UserPass {
                    username: username.to_string(),
                    password: password.to_string(),
                },
            )
            .await
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[tokio::test]
    async fn upserted_user_logs_in_with_exactly_its_policies() {
        let storage = MemStorage::default();
        UserPassAuth::upsert_user(&storage, "liaison", PASSWORD, names(&["liaison"]))
            .await
            .unwrap();

        let outcome = login(&storage, "liaison", PASSWORD).await.unwrap();
        assert_eq!(outcome.policies, names(&["liaison"]));
        assert_eq!(outcome.display_name, "liaison");
        // Same key scheme as bootstrap, so both paths see the same users.
        assert!(storage.0.lock().unwrap().contains_key("auth/userpass/users/liaison"));
    }

    /// Replace means replace: the old password stops working and the policy
    /// list is swapped, not merged.
    #[tokio::test]
    async fn upsert_replaces_password_and_policies() {
        let storage = MemStorage::default();
        UserPassAuth::upsert_user(&storage, "app", PASSWORD, names(&["a", "b"]))
            .await
            .unwrap();
        UserPassAuth::upsert_user(&storage, "app", "another long password", names(&["c"]))
            .await
            .unwrap();

        assert!(matches!(
            login(&storage, "app", PASSWORD).await,
            Err(AuthError::InvalidCredentials)
        ));
        let outcome = login(&storage, "app", "another long password").await.unwrap();
        assert_eq!(outcome.policies, names(&["c"]));
    }

    #[tokio::test]
    async fn read_user_returns_policies_and_never_the_hash() {
        let storage = MemStorage::default();
        UserPassAuth::upsert_user(&storage, "app", PASSWORD, names(&["p"]))
            .await
            .unwrap();

        let info = UserPassAuth::read_user(&storage, "app").await.unwrap().unwrap();
        assert_eq!(
            info,
            UserInfo {
                username: "app".into(),
                policies: names(&["p"]),
            }
        );
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("hash"), "{json}");
        assert!(!json.contains("argon2"), "{json}");

        assert_eq!(UserPassAuth::read_user(&storage, "nobody").await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_user_reports_whether_it_existed_and_blocks_login() {
        let storage = MemStorage::default();
        UserPassAuth::upsert_user(&storage, "app", PASSWORD, vec![])
            .await
            .unwrap();

        assert!(UserPassAuth::delete_user(&storage, "app").await.unwrap());
        assert!(!UserPassAuth::delete_user(&storage, "app").await.unwrap());
        assert!(matches!(
            login(&storage, "app", PASSWORD).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// Bootstrap credentials come from config and must keep working even when
    /// they would fail the HTTP rules.
    #[tokio::test]
    async fn create_user_skips_validation_for_bootstrap() {
        let storage = MemStorage::default();
        UserPassAuth::create_user(&storage, "admin@example.com", "change-me", names(&["root"]))
            .await
            .unwrap();
        let outcome = login(&storage, "admin@example.com", "change-me").await.unwrap();
        assert_eq!(outcome.policies, names(&["root"]));
    }

    /// A matching user is left alone (same stored hash, so no re-salting);
    /// a changed password or policy list is written and takes effect.
    #[tokio::test]
    async fn ensure_user_writes_only_what_differs() {
        let storage = MemStorage::default();
        let stored = |s: &MemStorage| {
            s.0.lock().unwrap()["auth/userpass/users/app"].value.clone()
        };

        assert!(UserPassAuth::ensure_user(&storage, "app", PASSWORD, names(&["p"])).await.unwrap());
        let first = stored(&storage);
        assert!(!UserPassAuth::ensure_user(&storage, "app", PASSWORD, names(&["p"])).await.unwrap());
        assert_eq!(stored(&storage), first, "an unchanged user was rewritten");

        assert!(UserPassAuth::ensure_user(&storage, "app", PASSWORD, names(&["q"])).await.unwrap());
        assert_eq!(login(&storage, "app", PASSWORD).await.unwrap().policies, names(&["q"]));

        let rotated = "a rotated long password";
        assert!(UserPassAuth::ensure_user(&storage, "app", rotated, names(&["q"])).await.unwrap());
        assert!(matches!(
            login(&storage, "app", PASSWORD).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(login(&storage, "app", rotated).await.is_ok());
    }

    #[tokio::test]
    async fn ensure_user_validates_like_upsert() {
        let storage = MemStorage::default();
        let result = UserPassAuth::ensure_user(&storage, "app", "too short", vec![]).await;
        assert!(matches!(result, Err(AuthError::InvalidRequest(_))));
        assert!(storage.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_upsert_writes_nothing() {
        let storage = MemStorage::default();
        for (username, password, policies) in [
            (".hidden", PASSWORD, vec![]),
            ("app", "too short", vec![]),
            ("app", PASSWORD, names(&["ok", ""])),
        ] {
            let result = UserPassAuth::upsert_user(&storage, username, password, policies).await;
            assert!(
                matches!(result, Err(AuthError::InvalidRequest(_))),
                "{username}/{password} was accepted"
            );
        }
        assert!(storage.0.lock().unwrap().is_empty());
    }

    #[test]
    fn username_rules() {
        for ok in ["a", "typednotes-app", "svc_1.v2", "A-Z.0_9", &"x".repeat(64), "a."] {
            assert!(validate_username(ok).is_ok(), "{ok:?} rejected");
        }
        for bad in [
            "",
            &"x".repeat(65),
            ".",
            ".env",
            "a/b",
            "../root",
            "with space",
            "émile",
            "a@b",
            "a%2Fb",
        ] {
            assert!(
                matches!(validate_username(bad), Err(AuthError::InvalidRequest(_))),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn password_length_counts_characters() {
        assert!(validate_password("12345678901").is_err());
        assert!(validate_password("123456789012").is_ok());
        // 11 characters but 22 bytes: still too short.
        assert!(validate_password("ééééééééééé").is_err());
    }

    #[test]
    fn policy_names_must_be_non_empty_but_the_list_may_be_empty() {
        assert!(validate_policies(&[]).is_ok());
        assert!(validate_policies(&names(&["a", "b"])).is_ok());
        assert!(validate_policies(&names(&[""])).is_err());
    }
}
