//! Group registry for RADIO-DISH: tracks which groups a DISH peer has joined.

use heapless::Vec;

/// Errors returned by [`GroupTable`] operations.
#[derive(Debug, PartialEq)]
pub enum GroupError {
    /// The table already holds `MAX_ENTRIES` groups.
    TableFull,
    /// The supplied group name exceeds `MAX_GROUP_LEN` bytes.
    GroupTooLong,
}

/// Bounded per-peer group membership table with exact matching.
///
/// `MAX_ENTRIES` — maximum simultaneous groups stored.
/// `MAX_GROUP_LEN` — maximum byte length of a single group name.
pub struct GroupTable<const MAX_ENTRIES: usize, const MAX_GROUP_LEN: usize> {
    entries: Vec<Vec<u8, MAX_GROUP_LEN>, MAX_ENTRIES>,
}

impl<const MAX_ENTRIES: usize, const MAX_GROUP_LEN: usize> GroupTable<MAX_ENTRIES, MAX_GROUP_LEN> {
    /// Create an empty group table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<const MAX_ENTRIES: usize, const MAX_GROUP_LEN: usize> Default
    for GroupTable<MAX_ENTRIES, MAX_GROUP_LEN>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_ENTRIES: usize, const MAX_GROUP_LEN: usize> GroupTable<MAX_ENTRIES, MAX_GROUP_LEN> {
    /// Register a group membership (JOIN).
    ///
    /// Returns `Err` if the table is full or the group exceeds `MAX_GROUP_LEN`.
    /// Silently succeeds (no duplicate added) if the group is already present.
    ///
    /// # Panics
    /// Panics if `group.len() <= MAX_GROUP_LEN` but the internal `Vec` fails to extend
    /// (should be impossible given the length check).
    ///
    /// # Errors
    /// Returns `GroupError::GroupTooLong` if the group exceeds `MAX_GROUP_LEN`.
    /// Returns `GroupError::TableFull` if the table already holds `MAX_ENTRIES` groups.
    pub fn join(&mut self, group: &[u8]) -> Result<(), GroupError> {
        if group.len() > MAX_GROUP_LEN {
            return Err(GroupError::GroupTooLong);
        }
        // Duplicate detection — skip if already present.
        for entry in &self.entries {
            if entry.as_slice() == group {
                return Ok(());
            }
        }
        let mut v: Vec<u8, MAX_GROUP_LEN> = Vec::new();
        v.extend_from_slice(group)
            .expect("group length checked above");
        self.entries.push(v).map_err(|_| GroupError::TableFull)
    }

    /// Remove a group membership (LEAVE). No-op if the group is not present.
    pub fn leave(&mut self, group: &[u8]) {
        if let Some(pos) = self.entries.iter().position(|e| e.as_slice() == group) {
            self.entries.swap_remove(pos);
        }
    }

    /// Returns `true` if `group` exactly matches a stored entry.
    #[must_use]
    pub fn matches(&self, group: &[u8]) -> bool {
        self.entries.iter().any(|e| e.as_slice() == group)
    }

    /// Number of active group memberships.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no groups are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{GroupError, GroupTable};

    #[test]
    fn empty_table_matches_nothing() {
        let table: GroupTable<8, 16> = GroupTable::new();
        assert!(!table.matches(b"foo"));
    }

    #[test]
    fn join_exact_match() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.join(b"foo").unwrap();
        assert!(table.matches(b"foo"));
    }

    #[test]
    fn join_does_not_prefix_match() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.join(b"foo").unwrap();
        assert!(!table.matches(b"foobar"));
        assert!(!table.matches(b"fo"));
    }

    #[test]
    fn leave_removes_group() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.join(b"foo").unwrap();
        table.leave(b"foo");
        assert!(!table.matches(b"foo"));
    }

    #[test]
    fn leave_nonexistent_is_noop() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.leave(b"foo");
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn multiple_groups_exact_match() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.join(b"foo").unwrap();
        table.join(b"bar").unwrap();
        assert!(table.matches(b"foo"));
        assert!(table.matches(b"bar"));
        assert!(!table.matches(b"baz"));
    }

    #[test]
    fn table_full_returns_err() {
        let mut table: GroupTable<2, 8> = GroupTable::new();
        assert!(table.join(b"first").is_ok());
        assert!(table.join(b"second").is_ok());
        assert_eq!(table.join(b"third"), Err(GroupError::TableFull));
    }

    #[test]
    fn group_too_long_returns_err() {
        let mut table: GroupTable<8, 4> = GroupTable::new();
        assert_eq!(table.join(b"toolong"), Err(GroupError::GroupTooLong));
    }

    #[test]
    fn len_and_is_empty() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        table.join(b"foo").unwrap();
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
        table.leave(b"foo");
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_join_does_not_add_twice() {
        let mut table: GroupTable<8, 16> = GroupTable::new();
        table.join(b"foo").unwrap();
        table.join(b"foo").unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.matches(b"foo"));
    }

    #[test]
    fn join_at_max_length_succeeds() {
        let mut table: GroupTable<8, 4> = GroupTable::new();
        table.join(b"abcd").unwrap();
        assert!(table.matches(b"abcd"));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn leave_at_max_length_removes_group() {
        let mut table: GroupTable<8, 4> = GroupTable::new();
        table.join(b"abcd").unwrap();
        table.leave(b"abcd");
        assert!(!table.matches(b"abcd"));
        assert!(table.is_empty());
    }
}
