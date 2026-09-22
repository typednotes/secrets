use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::lease::Lease;
use crate::storage::StorageBackend;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("not found")]
    NotFound,
    #[error("operation not supported by this engine")]
    Unsupported,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("provider rejected the request: {0}")]
    Provider(String),
    #[error("engine error: {0}")]
    Other(String),
}

pub type EngineResult<T> = Result<T, EngineError>;

/// Which of the five delegation shapes an engine implements. The shape is the
/// single most useful thing to know about a credential, because it says what a
/// lease can actually promise — see `docs/delegation/README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialShape {
    /// A — minted on demand and destroyed on demand. A lease means what it says.
    MintAndRevoke,
    /// B — minted on demand, but the provider cannot un-mint it. TTL is the
    /// only containment, and `revoke()` is advisory.
    MintExpiryOnly,
    /// C — the durable half stays here, only a short access token is handed out.
    RefreshBroker,
    /// D — nothing is mintable; this is encrypted custody plus rotation.
    StaticCustody,
    /// E — no credential exists anywhere; the consumer's own identity is trusted.
    Federation,
}

impl CredentialShape {
    /// Whether revoking the lease destroys **the credential the consumer
    /// received**. That is the only question a consumer is actually asking, and
    /// answering it narrowly keeps the `_doc` block honest.
    ///
    /// Only shape A can say yes. A refresh broker can kill the durable half —
    /// which stops future issuance — but the access token already handed out
    /// lives until it expires, so from the consumer's point of view its lease
    /// is not revocable either.
    pub fn revocable(self) -> bool {
        matches!(self, Self::MintAndRevoke)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MintAndRevoke => "mint-and-revoke",
            Self::MintExpiryOnly => "mint-expiry-only",
            Self::RefreshBroker => "refresh-broker",
            Self::StaticCustody => "static-custody",
            Self::Federation => "federation",
        }
    }
}

/// The lifetime envelope a provider allows, so a caller can see why it got the
/// TTL it got instead of guessing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlDoc {
    pub min_seconds: Option<i64>,
    pub max_seconds: Option<i64>,
    /// True when the provider dictates one lifetime and ignores our request.
    pub fixed: bool,
    pub note: String,
}

impl TtlDoc {
    pub fn fixed(seconds: i64, note: impl Into<String>) -> Self {
        Self {
            min_seconds: Some(seconds),
            max_seconds: Some(seconds),
            fixed: true,
            note: note.into(),
        }
    }

    pub fn range(min: i64, max: i64, note: impl Into<String>) -> Self {
        Self {
            min_seconds: Some(min),
            max_seconds: Some(max),
            fixed: false,
            note: note.into(),
        }
    }
}

/// One route an engine answers, described for the `help` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDoc {
    pub path: String,
    pub methods: Vec<String>,
    pub capability: String,
    pub description: String,
}

impl PathDoc {
    pub fn new(
        path: impl Into<String>,
        methods: &[&str],
        capability: &str,
        description: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            capability: capability.to_string(),
            description: description.into(),
        }
    }
}

/// Everything an operator or a consumer needs to know about an engine without
/// leaving the API: which provider, which mechanism, what a lease is worth,
/// what `revoke()` really does, and what the server had to be trusted with.
///
/// Served at `GET /v1/{mount}/help`, and its operative fields are echoed in
/// the `_doc` block of every credential response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineDoc {
    pub provider: String,
    /// The concrete provider API being used, e.g. "GitHub App installation tokens".
    pub mechanism: String,
    pub shape: CredentialShape,
    /// Whether revoking a lease destroys the credential the consumer holds.
    /// Must agree with `shape.revocable()` — the server asserts this, because
    /// an engine that overstates it would mislead every caller.
    pub revocable: bool,
    /// What `revoke()` does *in reality* — including "nothing, the credential
    /// keeps working until it expires", which is the truth for three of the
    /// providers here and must not be dressed up.
    pub revoke_effect: String,
    pub ttl: TtlDoc,
    pub scoping: String,
    /// What long-lived secret the server must hold, or "none" under federation.
    pub root_credential: String,
    pub paths: Vec<PathDoc>,
    pub docs_url: Option<String>,
    /// Sharp edges worth knowing before depending on this engine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

/// The result of minting a credential: what the caller gets, the lease that
/// governs it, and what it was narrowed to.
#[derive(Debug)]
pub struct GeneratedCredential {
    pub data: serde_json::Value,
    pub lease: Lease,
    /// Human-readable scope of *this* credential — e.g. `["repo:reports",
    /// "contents:read"]`. Echoed into the response `_doc` so a consumer can
    /// see what it was granted rather than inferring it.
    pub scoped_to: Vec<String>,
    /// Overrides the engine's shape for this one credential. Needed because a
    /// single engine can offer mechanisms with different guarantees — the AWS
    /// engine mints both un-revocable STS sessions and revocable per-lease IAM
    /// users — and a `_doc` block that averaged over them would be a lie.
    pub shape: Option<CredentialShape>,
    /// Overrides the engine's `revoke_effect` for this one credential.
    pub revoke_effect: Option<String>,
}

impl GeneratedCredential {
    /// The common case: this credential behaves exactly as the engine's own
    /// `doc()` describes.
    pub fn new(data: serde_json::Value, lease: Lease, scoped_to: Vec<String>) -> Self {
        Self {
            data,
            lease,
            scoped_to,
            shape: None,
            revoke_effect: None,
        }
    }

    /// Declares that this credential's guarantees differ from the engine's
    /// headline shape.
    pub fn with_shape(mut self, shape: CredentialShape, revoke_effect: impl Into<String>) -> Self {
        self.shape = Some(shape);
        self.revoke_effect = Some(revoke_effect.into());
        self
    }
}

#[async_trait]
pub trait SecretsEngine: Send + Sync {
    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<serde_json::Value>;
    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()>;
    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()>;
    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>>;

    /// Self-documentation. Every engine must answer this — an engine that
    /// cannot say what its credentials are worth has no business minting them.
    fn doc(&self) -> EngineDoc;

    /// Dynamic-secret engines (e.g. Postgres) override these; static
    /// engines (e.g. KV) inherit the default `Unsupported`.
    async fn generate(
        &self,
        _storage: &dyn StorageBackend,
        _role: &str,
    ) -> EngineResult<GeneratedCredential> {
        Err(EngineError::Unsupported)
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, _lease: &Lease) -> EngineResult<()> {
        Err(EngineError::Unsupported)
    }
}
