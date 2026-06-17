//! ACL / policy engine (PRD Phase 3, FR4) — "ACLs as code".
//!
//! Access is expressed as tag-based allow-rules: a device tagged in a rule's
//! `src` may reach a device tagged in that rule's `dst`. Matching is **deny by
//! default** — a peer is reachable only if some rule permits it. The token `*`
//! matches any tag (and is satisfied even by a device with no tags).
//!
//! Note: until authentication (OIDC) lands, device tags are self-declared at
//! registration, so policy here is structural, not yet an authorization
//! boundary. Tag authorization arrives with auth in a later increment.

use serde::Deserialize;

/// A single allow-rule: any `src` tag may reach any `dst` tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AclRule {
    /// Source tags (or `*`).
    pub src: Vec<String>,
    /// Destination tags (or `*`).
    pub dst: Vec<String>,
}

/// The access policy: a set of allow-rules, or allow-all (full mesh).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    /// When true, every device may reach every other (Phase 3 M1 default).
    #[serde(default)]
    pub allow_all: bool,
    /// Allow-rules evaluated when `allow_all` is false (deny by default).
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

impl Policy {
    /// A full-mesh policy: everyone may reach everyone.
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            rules: Vec::new(),
        }
    }

    /// A deny-by-default policy with the given allow-rules.
    pub fn from_rules(rules: Vec<AclRule>) -> Self {
        Self {
            allow_all: false,
            rules,
        }
    }

    /// Parse a policy from TOML (e.g. `allow_all = true`, or `[[rules]]` tables).
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Whether a device tagged `src_tags` may reach one tagged `dst_tags`.
    pub fn allows(&self, src_tags: &[String], dst_tags: &[String]) -> bool {
        if self.allow_all {
            return true;
        }
        self.rules
            .iter()
            .any(|r| tag_match(&r.src, src_tags) && tag_match(&r.dst, dst_tags))
    }
}

/// True if any rule tag is `*` or is present in the device's tags.
fn tag_match(rule_tags: &[String], device_tags: &[String]) -> bool {
    rule_tags
        .iter()
        .any(|rt| rt == "*" || device_tags.iter().any(|dt| dt == rt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(s: &[&str]) -> Vec<String> {
        s.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn allow_all_permits_everything() {
        let p = Policy::allow_all();
        assert!(p.allows(&tags(&["x"]), &tags(&["y"])));
        assert!(p.allows(&[], &[]));
    }

    #[test]
    fn rules_are_directional_and_deny_by_default() {
        // "dev" may reach "server", but not the reverse, and not dev->dev.
        let p = Policy::from_rules(vec![AclRule {
            src: tags(&["dev"]),
            dst: tags(&["server"]),
        }]);
        assert!(p.allows(&tags(&["dev"]), &tags(&["server"])));
        assert!(!p.allows(&tags(&["server"]), &tags(&["dev"])));
        assert!(!p.allows(&tags(&["dev"]), &tags(&["dev"])));
        assert!(!p.allows(&tags(&["other"]), &tags(&["server"])));
    }

    #[test]
    fn wildcard_matches_any_tag() {
        let p = Policy::from_rules(vec![AclRule {
            src: tags(&["admin"]),
            dst: tags(&["*"]),
        }]);
        assert!(p.allows(&tags(&["admin"]), &tags(&["anything"])));
        assert!(p.allows(&tags(&["admin"]), &[])); // `*` matches even no tags
        assert!(!p.allows(&tags(&["user"]), &tags(&["anything"])));
    }

    #[test]
    fn parses_from_toml() {
        let p = Policy::from_toml(
            r#"
            [[rules]]
            src = ["dev"]
            dst = ["server", "db"]
            "#,
        )
        .unwrap();
        assert!(!p.allow_all);
        assert_eq!(p.rules.len(), 1);
        assert!(p.allows(&tags(&["dev"]), &tags(&["db"])));
        assert!(!p.allows(&tags(&["dev"]), &tags(&["web"])));
    }
}
