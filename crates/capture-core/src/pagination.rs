//! Shared cursor pagination primitives for local and hosted HTTP APIs.

use std::{error::Error, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const CURSOR_VERSION: u8 = 1;
const CURSOR_DIGEST_DOMAIN: &[u8] = b"ecp/cursor/v1\0";
/// Reject cursors before decoding or allocating an unbounded payload.
pub const MAX_CURSOR_LENGTH: usize = 2_048;
const MAX_CURSOR_PAYLOAD_LENGTH: usize = 1_536;

/// Query fields shared by every paginated list route.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PageQuery {
    /// Number of items to return. Each route documents its own maximum.
    #[cfg_attr(feature = "openapi", schema(minimum = 1))]
    pub limit: Option<u32>,
    /// Opaque continuation token returned by the same route and filter set.
    pub cursor: Option<String>,
}

impl PageQuery {
    /// Validates a route's default and maximum page size without silently
    /// changing a caller's request.
    pub fn limit(&self, default: usize, maximum: usize) -> Result<usize, PaginationError> {
        if default == 0 || maximum == 0 || default > maximum {
            return Err(PaginationError::InvalidConfiguration);
        }
        let requested = self.limit.map_or(default, |limit| limit as usize);
        if requested == 0 || requested > maximum {
            return Err(PaginationError::InvalidLimit { maximum });
        }
        Ok(requested)
    }
}

/// Uniform response shape for every paginated list route.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Cursor for the next page, or `null` when this page exhausts the query.
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Builds a page from a query that fetched `limit + 1` rows. The next
    /// cursor always points immediately after the last returned item.
    pub fn from_limit_plus_one<P, F>(
        mut items: Vec<T>,
        limit: usize,
        scope: &CursorScope,
        position: F,
    ) -> Result<Self, PaginationError>
    where
        P: Serialize,
        F: FnOnce(&T) -> P,
    {
        if limit == 0 {
            return Err(PaginationError::InvalidLimit { maximum: 0 });
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = if has_more {
            let last = items.last().ok_or(PaginationError::InvalidPage)?;
            Some(encode_cursor(scope, &position(last))?)
        } else {
            None
        };
        Ok(Self { items, next_cursor })
    }
}

/// Hash-bound identity for one route, filter set, and sort order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorScope([u8; 32]);

impl CursorScope {
    /// Creates a scope from structured filters so delimiter collisions cannot
    /// make two different requests share a cursor namespace.
    pub fn new<F: Serialize>(
        route: &str,
        filters: &F,
        order: &str,
    ) -> Result<Self, PaginationError> {
        if route.is_empty() || order.is_empty() {
            return Err(PaginationError::InvalidConfiguration);
        }
        let serialized = serde_json::to_vec(&(route, filters, order))
            .map_err(|_| PaginationError::Serialization)?;
        Ok(Self(Sha256::digest(serialized).into()))
    }
}

#[derive(Deserialize, Serialize)]
struct CursorBody<P> {
    version: u8,
    scope: String,
    position: P,
}

#[derive(Deserialize, Serialize)]
struct CursorEnvelope<P> {
    body: CursorBody<P>,
    digest: String,
}

/// Encodes a typed sort position into an opaque, versioned continuation token.
pub fn encode_cursor<P: Serialize>(
    scope: &CursorScope,
    position: &P,
) -> Result<String, PaginationError> {
    let body = CursorBody {
        version: CURSOR_VERSION,
        scope: hex::encode(scope.0),
        position: serde_json::to_value(position).map_err(|_| PaginationError::Serialization)?,
    };
    let body_bytes = serde_json::to_vec(&body).map_err(|_| PaginationError::Serialization)?;
    let envelope = CursorEnvelope {
        digest: cursor_digest(&body_bytes),
        body,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| PaginationError::Serialization)?;
    if bytes.len() > MAX_CURSOR_PAYLOAD_LENGTH {
        return Err(PaginationError::CursorTooLong);
    }
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > MAX_CURSOR_LENGTH {
        return Err(PaginationError::CursorTooLong);
    }
    Ok(encoded)
}

/// Decodes a cursor only when its version, corruption checksum, and request
/// scope match the current query. The checksum is not a MAC; SQL queries must
/// still enforce authorization and visibility.
pub fn decode_cursor<P: DeserializeOwned>(
    scope: &CursorScope,
    cursor: &str,
) -> Result<P, PaginationError> {
    if cursor.is_empty() {
        return Err(PaginationError::MalformedCursor);
    }
    if cursor.len() > MAX_CURSOR_LENGTH {
        return Err(PaginationError::CursorTooLong);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| PaginationError::MalformedCursor)?;
    if bytes.len() > MAX_CURSOR_PAYLOAD_LENGTH {
        return Err(PaginationError::CursorTooLong);
    }
    let envelope: CursorEnvelope<serde_json::Value> =
        serde_json::from_slice(&bytes).map_err(|_| PaginationError::MalformedCursor)?;
    if envelope.body.version != CURSOR_VERSION {
        return Err(PaginationError::UnsupportedCursorVersion);
    }
    let body_bytes =
        serde_json::to_vec(&envelope.body).map_err(|_| PaginationError::MalformedCursor)?;
    if !constant_time_eq(
        envelope.digest.as_bytes(),
        cursor_digest(&body_bytes).as_bytes(),
    ) {
        return Err(PaginationError::CursorChecksum);
    }
    let expected_scope = hex::encode(scope.0);
    if !constant_time_eq(envelope.body.scope.as_bytes(), expected_scope.as_bytes()) {
        return Err(PaginationError::CursorScope);
    }
    serde_json::from_value(envelope.body.position).map_err(|_| PaginationError::MalformedCursor)
}

fn cursor_digest(body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(CURSOR_DIGEST_DOMAIN);
    digest.update(body);
    hex::encode(digest.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Typed failures that list handlers map to stable `400` responses, except
/// serialization and configuration failures, which indicate server bugs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaginationError {
    InvalidLimit { maximum: usize },
    CursorTooLong,
    MalformedCursor,
    UnsupportedCursorVersion,
    CursorChecksum,
    CursorScope,
    InvalidPage,
    Serialization,
    InvalidConfiguration,
}

impl PaginationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimit { .. } => "invalid_page_limit",
            Self::CursorTooLong => "cursor_too_long",
            Self::MalformedCursor => "invalid_cursor",
            Self::UnsupportedCursorVersion => "unsupported_cursor_version",
            Self::CursorChecksum => "invalid_cursor",
            Self::CursorScope => "cursor_scope_mismatch",
            Self::InvalidPage | Self::Serialization | Self::InvalidConfiguration => {
                "pagination_configuration_error"
            }
        }
    }

    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidLimit { .. }
                | Self::CursorTooLong
                | Self::MalformedCursor
                | Self::UnsupportedCursorVersion
                | Self::CursorChecksum
                | Self::CursorScope
        )
    }
}

impl fmt::Display for PaginationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { maximum } => {
                write!(formatter, "page limit must be between 1 and {maximum}")
            }
            Self::CursorTooLong => formatter.write_str("cursor exceeds the maximum length"),
            Self::MalformedCursor => formatter.write_str("cursor is malformed"),
            Self::UnsupportedCursorVersion => {
                formatter.write_str("cursor version is not supported")
            }
            Self::CursorChecksum => formatter.write_str("cursor checksum failed"),
            Self::CursorScope => {
                formatter.write_str("cursor does not belong to this route and filter set")
            }
            Self::InvalidPage => formatter.write_str("page cannot produce a continuation cursor"),
            Self::Serialization => formatter.write_str("cursor serialization failed"),
            Self::InvalidConfiguration => formatter.write_str("pagination is misconfigured"),
        }
    }
}

impl Error for PaginationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Position {
        created_at_unix_ms: u64,
        id: String,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct OtherPosition {
        event_id: u64,
    }

    #[derive(Serialize)]
    struct Filters<'a> {
        provider: Option<&'a str>,
        search: Option<&'a str>,
    }

    fn scope(route: &str, provider: Option<&str>) -> CursorScope {
        CursorScope::new(
            route,
            &Filters {
                provider,
                search: None,
            },
            "created_at_unix_ms desc, id desc",
        )
        .unwrap()
    }

    #[test]
    fn cursor_round_trip_preserves_tied_sort_position() {
        let scope = scope("/v1/traces", Some("openai"));
        let position = Position {
            created_at_unix_ms: 42,
            id: "trc-b".into(),
        };
        let cursor = encode_cursor(&scope, &position).unwrap();
        assert_eq!(decode_cursor(&scope, &cursor), Ok(position));
    }

    #[test]
    fn cursor_rejects_changed_route_or_filters() {
        let original = scope("/v1/traces", Some("openai"));
        let cursor = encode_cursor(
            &original,
            &Position {
                created_at_unix_ms: 42,
                id: "trc-b".into(),
            },
        )
        .unwrap();
        assert_eq!(
            decode_cursor::<Position>(&scope("/v1/activity", Some("openai")), &cursor),
            Err(PaginationError::CursorScope)
        );
        assert_eq!(
            decode_cursor::<OtherPosition>(&scope("/v1/providers", Some("openai")), &cursor),
            Err(PaginationError::CursorScope)
        );
        assert_eq!(
            decode_cursor::<Position>(&scope("/v1/traces", Some("anthropic")), &cursor),
            Err(PaginationError::CursorScope)
        );
    }

    #[test]
    fn cursor_rejects_malformed_oversized_and_tampered_values() {
        let scope = scope("/v1/traces", None);
        assert_eq!(
            decode_cursor::<Position>(&scope, "not base64!"),
            Err(PaginationError::MalformedCursor)
        );
        assert_eq!(
            decode_cursor::<Position>(&scope, &"a".repeat(MAX_CURSOR_LENGTH + 1)),
            Err(PaginationError::CursorTooLong)
        );
        let cursor = encode_cursor(
            &scope,
            &Position {
                created_at_unix_ms: 42,
                id: "trc-b".into(),
            },
        )
        .unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(cursor).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        envelope["body"]["position"]["id"] = serde_json::Value::String("trc-c".into());
        let tampered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());
        assert_eq!(
            decode_cursor::<Position>(&scope, &tampered),
            Err(PaginationError::CursorChecksum)
        );
    }

    #[test]
    fn cursor_rejects_unknown_version() {
        let scope = scope("/v1/traces", None);
        let body = CursorBody {
            version: CURSOR_VERSION + 1,
            scope: hex::encode(scope.0),
            position: Position {
                created_at_unix_ms: 42,
                id: "trc-b".into(),
            },
        };
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let cursor = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&CursorEnvelope {
                digest: cursor_digest(&body_bytes),
                body,
            })
            .unwrap(),
        );
        assert_eq!(
            decode_cursor::<Position>(&scope, &cursor),
            Err(PaginationError::UnsupportedCursorVersion)
        );
    }

    #[test]
    fn page_uses_limit_plus_one_and_last_returned_item() {
        let scope = scope("/v1/traces", None);
        let rows = vec![
            Position {
                created_at_unix_ms: 3,
                id: "trc-c".into(),
            },
            Position {
                created_at_unix_ms: 2,
                id: "trc-b".into(),
            },
            Position {
                created_at_unix_ms: 1,
                id: "trc-a".into(),
            },
        ];
        let page = Page::from_limit_plus_one(rows, 2, &scope, Clone::clone).unwrap();
        assert_eq!(page.items.len(), 2);
        let next: Position = decode_cursor(&scope, page.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(next.id, "trc-b");
    }

    #[test]
    fn exhausted_pages_have_no_cursor() {
        let scope = scope("/v1/traces", None);
        for rows in [Vec::new(), vec![1], vec![1, 2]] {
            let page = Page::from_limit_plus_one(rows, 2, &scope, |value| *value).unwrap();
            assert_eq!(page.next_cursor, None);
        }
    }

    #[test]
    fn limits_are_explicitly_bounded() {
        let query = PageQuery::default();
        assert_eq!(query.limit(50, 200), Ok(50));
        assert_eq!(
            PageQuery {
                limit: Some(0),
                cursor: None
            }
            .limit(50, 200),
            Err(PaginationError::InvalidLimit { maximum: 200 })
        );
        assert_eq!(
            PageQuery {
                limit: Some(201),
                cursor: None
            }
            .limit(50, 200),
            Err(PaginationError::InvalidLimit { maximum: 200 })
        );
    }
}
