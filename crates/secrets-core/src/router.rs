use std::sync::Arc;

use crate::engine::SecretsEngine;

pub struct EngineMount {
    pub prefix: String,
    pub engine: Arc<dyn SecretsEngine>,
}

/// Maps request paths onto mounted secrets engines by longest-prefix match —
/// the same dispatch model `Policy::is_allowed` uses for ACLs. Registering a
/// new engine means adding one `EngineMount` here, nowhere else.
#[derive(Default)]
pub struct Router {
    mounts: Vec<EngineMount>,
}

impl Router {
    pub fn new(mounts: Vec<EngineMount>) -> Self {
        Self { mounts }
    }

    /// Returns the matching mount and the path remainder relative to it.
    pub fn resolve<'a>(&self, path: &'a str) -> Option<(&EngineMount, &'a str)> {
        self.mounts
            .iter()
            .filter(|m| path.starts_with(&m.prefix))
            .max_by_key(|m| m.prefix.len())
            .map(move |m| (m, path.strip_prefix(&m.prefix).unwrap_or("")))
    }
}
