use serde::{Deserialize, Serialize};

use crate::storage::{StorageBackend, StorageEntry, StorageError};

const POLICY_PREFIX: &str = "sys/policy/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Read,
    Create,
    Update,
    Delete,
    List,
    Sudo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRule {
    pub prefix: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<PathRule>,
}

impl Policy {
    /// Deny-by-default, longest-prefix-match evaluation.
    pub fn is_allowed(&self, path: &str, capability: Capability) -> bool {
        self.rules
            .iter()
            .filter(|r| path.starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .is_some_and(|r| r.capabilities.contains(&capability))
    }
}

pub fn evaluate(policies: &[Policy], path: &str, capability: Capability) -> bool {
    policies.iter().any(|p| p.is_allowed(path, capability))
}

pub async fn store_policy(storage: &dyn StorageBackend, policy: &Policy) -> Result<(), StorageError> {
    let path = format!("{POLICY_PREFIX}{}", policy.name);
    let value = serde_json::to_vec(policy).map_err(|e| StorageError::Backend(e.to_string()))?;
    storage
        .put(
            &path,
            StorageEntry {
                value,
                expires_at: None,
            },
        )
        .await
}

pub async fn get_policy(
    storage: &dyn StorageBackend,
    name: &str,
) -> Result<Option<Policy>, StorageError> {
    let path = format!("{POLICY_PREFIX}{name}");
    let Some(entry) = storage.get(&path).await? else {
        return Ok(None);
    };
    let policy: Policy =
        serde_json::from_slice(&entry.value).map_err(|e| StorageError::Backend(e.to_string()))?;
    Ok(Some(policy))
}

pub async fn delete_policy(storage: &dyn StorageBackend, name: &str) -> Result<(), StorageError> {
    storage.delete(&format!("{POLICY_PREFIX}{name}")).await
}

/// Loads named policies, silently skipping any that no longer exist (e.g. a
/// token referencing a since-deleted policy).
pub async fn load_policies(
    storage: &dyn StorageBackend,
    names: &[String],
) -> Result<Vec<Policy>, StorageError> {
    let mut policies = Vec::with_capacity(names.len());
    for name in names {
        if let Some(policy) = get_policy(storage, name).await? {
            policies.push(policy);
        }
    }
    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: Vec<(&str, Vec<Capability>)>) -> Policy {
        Policy {
            name: "test".into(),
            rules: rules
                .into_iter()
                .map(|(prefix, capabilities)| PathRule {
                    prefix: prefix.to_string(),
                    capabilities,
                })
                .collect(),
        }
    }

    #[test]
    fn deny_by_default() {
        let p = policy(vec![]);
        assert!(!p.is_allowed("secret/foo", Capability::Read));
    }

    #[test]
    fn longest_prefix_wins() {
        let p = policy(vec![
            ("secret/", vec![Capability::Read]),
            ("secret/admin/", vec![Capability::Sudo]),
        ]);
        assert!(p.is_allowed("secret/foo", Capability::Read));
        assert!(!p.is_allowed("secret/admin/x", Capability::Read));
        assert!(p.is_allowed("secret/admin/x", Capability::Sudo));
    }

    #[test]
    fn evaluate_across_multiple_policies() {
        let a = policy(vec![("secret/", vec![Capability::Read])]);
        let b = policy(vec![("sys/", vec![Capability::Sudo])]);
        assert!(evaluate(&[a.clone(), b.clone()], "secret/foo", Capability::Read));
        assert!(evaluate(&[a, b], "sys/policy", Capability::Sudo));
    }
}
