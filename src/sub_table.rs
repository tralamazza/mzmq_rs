//! Subscription table for PUB-SUB: tracks active prefix filters from connected SUB peers.

use heapless::Vec;

/// Errors returned by [`SubTable`] operations.
#[derive(Debug, PartialEq)]
pub enum SubError {
    /// The table already holds `MAX_ENTRIES` subscriptions.
    TableFull,
    /// The supplied prefix exceeds `MAX_PREFIX_LEN` bytes.
    PrefixTooLong,
}

/// Bounded per-peer subscription table with prefix filtering.
///
/// `MAX_ENTRIES` — maximum simultaneous subscriptions stored.
/// `MAX_PREFIX_LEN` — maximum byte length of a single prefix.
pub struct SubTable<const MAX_ENTRIES: usize, const MAX_PREFIX_LEN: usize> {
    entries: Vec<Vec<u8, MAX_PREFIX_LEN>, MAX_ENTRIES>,
}

impl<const MAX_ENTRIES: usize, const MAX_PREFIX_LEN: usize> SubTable<MAX_ENTRIES, MAX_PREFIX_LEN> {
    /// Create an empty subscription table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<const MAX_ENTRIES: usize, const MAX_PREFIX_LEN: usize> Default
    for SubTable<MAX_ENTRIES, MAX_PREFIX_LEN>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_ENTRIES: usize, const MAX_PREFIX_LEN: usize> SubTable<MAX_ENTRIES, MAX_PREFIX_LEN> {
    /// Register a subscription prefix.
    ///
    /// Returns `Err` if the table is full or the prefix exceeds `MAX_PREFIX_LEN`.
    /// Silently succeeds (no duplicate added) if the prefix is already present.
    ///
    /// **RFC 37 deviation:** ZMTP 3.1 requires subscriptions to be additive and
    /// not idempotent — two identical `SUBSCRIBE` frames should require two
    /// `CANCEL` frames to fully unsubscribe. This implementation deduplicates to
    /// conserve bounded table space on embedded targets; one `CANCEL` always
    /// removes the prefix regardless of how many `SUBSCRIBE` frames were received.
    ///
    /// # Panics
    /// Panics if `prefix.len() <= MAX_PREFIX_LEN` but the internal `Vec` fails to extend
    /// (should be impossible given the length check).
    ///
    /// # Errors
    /// Returns `SubError::PrefixTooLong` if the prefix exceeds `MAX_PREFIX_LEN`.
    /// Returns `SubError::TableFull` if the table already holds `MAX_ENTRIES` subscriptions.
    pub fn subscribe(&mut self, prefix: &[u8]) -> Result<(), SubError> {
        if prefix.len() > MAX_PREFIX_LEN {
            return Err(SubError::PrefixTooLong);
        }
        // Duplicate detection — skip if already present.
        for entry in &self.entries {
            if entry.as_slice() == prefix {
                return Ok(());
            }
        }
        let mut v: Vec<u8, MAX_PREFIX_LEN> = Vec::new();
        v.extend_from_slice(prefix)
            .expect("prefix length checked above");
        self.entries.push(v).map_err(|_| SubError::TableFull)
    }

    /// Remove a subscription prefix. No-op if the prefix is not present.
    pub fn cancel(&mut self, prefix: &[u8]) {
        if let Some(pos) = self.entries.iter().position(|e| e.as_slice() == prefix) {
            self.entries.swap_remove(pos);
        }
    }

    /// Returns `true` if at least one stored prefix is a prefix of `topic`.
    ///
    /// An empty stored prefix (`b""`) matches every topic.
    #[must_use]
    pub fn matches(&self, topic: &[u8]) -> bool {
        self.entries.iter().any(|e| topic.starts_with(e.as_slice()))
    }

    /// Number of active subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no subscriptions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{SubError, SubTable};

    #[test]
    fn empty_table_matches_nothing() {
        let table: SubTable<8, 16> = SubTable::new();
        assert!(!table.matches(b"foo"));
    }

    #[test]
    fn subscribe_empty_prefix_matches_all() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"").unwrap();
        assert!(table.matches(b"foo"));
        assert!(table.matches(b""));
        assert!(table.matches(b"anything"));
    }

    #[test]
    fn subscribe_prefix_matches_exact() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        assert!(table.matches(b"foo"));
    }

    #[test]
    fn subscribe_prefix_matches_longer_topic() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        assert!(table.matches(b"foobar"));
    }

    #[test]
    fn subscribe_prefix_does_not_match_shorter_topic() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foobar").unwrap();
        assert!(!table.matches(b"foo"));
    }

    #[test]
    fn subscribe_prefix_does_not_match_different_prefix() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        assert!(!table.matches(b"bar"));
    }

    #[test]
    fn cancel_removes_subscription() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        table.cancel(b"foo");
        assert!(!table.matches(b"foo"));
    }

    #[test]
    fn cancel_nonexistent_is_noop() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.cancel(b"foo");
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn multiple_subscriptions_any_match() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        table.subscribe(b"bar").unwrap();
        assert!(table.matches(b"fooX"));
        assert!(table.matches(b"barX"));
        assert!(!table.matches(b"baz"));
    }

    #[test]
    fn table_full_returns_err() {
        let mut table: SubTable<2, 8> = SubTable::new();
        assert!(table.subscribe(b"first").is_ok());
        assert!(table.subscribe(b"second").is_ok());
        assert_eq!(table.subscribe(b"third"), Err(SubError::TableFull));
    }

    #[test]
    fn prefix_too_long_returns_err() {
        let mut table: SubTable<8, 4> = SubTable::new();
        assert_eq!(table.subscribe(b"toolong"), Err(SubError::PrefixTooLong));
    }

    #[test]
    fn len_and_is_empty() {
        let mut table: SubTable<8, 16> = SubTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        table.subscribe(b"foo").unwrap();
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
        table.cancel(b"foo");
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_subscribe_does_not_add_twice() {
        let mut table: SubTable<8, 16> = SubTable::new();
        table.subscribe(b"foo").unwrap();
        table.subscribe(b"foo").unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.matches(b"foo"));
    }
}
