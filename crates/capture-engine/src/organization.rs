//! The organization a request, Trace, or setting belongs to.
//!
//! A multi-customer capture server keeps every organization's metadata,
//! artifacts and settings apart. The desktop app's local service is one user
//! and never needs more than the implicit organization its stores imply.

use std::fmt;

use crate::metadata_store::{MetadataResult, MetadataStoreError};

/// A validated organization identifier: 1 to 128 ASCII letters, digits, `.`,
/// `_` or `-`, so it is safe in SQL parameters, object-store prefixes and
/// logs. Hosted identifiers are capture-api organization IDs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OrganizationId(String);

impl OrganizationId {
    pub fn parse(value: impl Into<String>) -> MetadataResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || value.starts_with('.')
        {
            return Err(MetadataStoreError::InvalidInput("invalid_organization_id"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_bounded_and_path_safe() {
        for valid in ["default", "acct-0123abcd", "org_1.team-2"] {
            assert_eq!(OrganizationId::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", ".hidden", "a/b", "a b", "../x", &"x".repeat(129)] {
            assert!(OrganizationId::parse(invalid).is_err(), "{invalid}");
        }
    }
}
