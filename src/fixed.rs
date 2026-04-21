//! Fixed-capacity UTF-8 text buffers.
//!
//! These buffers keep the public `AgentError` path allocation-free by storing
//! payload text inline and truncating at valid UTF-8 boundaries when needed.

use crate::zeroization::Zeroize;
use std::fmt;

/// Default truncation marker used for bounded inline strings.
pub(crate) const TRUNCATION_INDICATOR: &str = "...[TRUNCATED]";

/// Inline UTF-8 string with fixed byte capacity.
pub(crate) struct FixedString<const N: usize> {
    len: usize,
    buf: [u8; N],
}

impl<const N: usize> FixedString<N> {
    /// Create an empty fixed-capacity string.
    pub(crate) const fn new() -> Self {
        Self {
            len: 0,
            buf: [0u8; N],
        }
    }

    /// Return the current contents as UTF-8.
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        // SAFETY: All writes preserve UTF-8 boundaries and only copy valid UTF-8 bytes.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    /// Current length in bytes.
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// `true` when the buffer is empty.
    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Remaining writable capacity in bytes.
    #[inline]
    pub(crate) const fn remaining(&self) -> usize {
        N.saturating_sub(self.len)
    }

    /// Clear the current contents and zeroize the backing storage.
    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    #[inline]
    pub(crate) fn clear(&mut self) {
        self.zeroize();
    }

    /// Duplicate the current value into a new fixed-capacity buffer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn duplicate(&self) -> Self {
        let mut copy = Self::new();
        copy.buf[..self.len].copy_from_slice(&self.buf[..self.len]);
        copy.len = self.len;
        copy
    }

    /// Truncate the buffer to `new_len` bytes and zeroize the removed tail.
    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    pub(crate) fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        self.buf[new_len..self.len].zeroize();
        self.len = new_len;
    }

    /// Replace the contents with `input`, truncating when it exceeds capacity.
    pub(crate) fn set_truncated(&mut self, input: &str, indicator: &str) {
        self.set_truncated_to(input, N, indicator);
    }

    /// Replace the contents with `input`, truncating to `max_bytes`.
    pub(crate) fn set_truncated_to(&mut self, input: &str, max_bytes: usize, indicator: &str) {
        self.zeroize();
        let capacity = N.min(max_bytes);
        if capacity == 0 {
            return;
        }

        if input.len() <= capacity {
            self.buf[..input.len()].copy_from_slice(input.as_bytes());
            self.len = input.len();
            return;
        }

        let indicator_len = valid_prefix_len(indicator, capacity);
        if indicator_len == 0 {
            return;
        }

        if capacity <= indicator.len() {
            self.buf[..indicator_len].copy_from_slice(&indicator.as_bytes()[..indicator_len]);
            self.len = indicator_len;
            return;
        }

        let mut prefix_len = capacity - indicator.len();
        while prefix_len > 0 && !input.is_char_boundary(prefix_len) {
            prefix_len -= 1;
        }

        if prefix_len == 0 {
            self.buf[..indicator_len].copy_from_slice(&indicator.as_bytes()[..indicator_len]);
            self.len = indicator_len;
            return;
        }

        self.buf[..prefix_len].copy_from_slice(&input.as_bytes()[..prefix_len]);
        self.buf[prefix_len..prefix_len + indicator.len()].copy_from_slice(indicator.as_bytes());
        self.len = prefix_len + indicator.len();
    }
}

impl<const N: usize> Default for FixedString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for FixedString<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.remaining() < s.len() {
            return Err(fmt::Error);
        }

        let end = self.len + s.len();
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for FixedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> Zeroize for FixedString<N> {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.len.zeroize();
    }
}

fn valid_prefix_len(input: &str, max_bytes: usize) -> usize {
    let mut len = input.len().min(max_bytes);
    while len > 0 && !input.is_char_boundary(len) {
        len -= 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::{FixedString, TRUNCATION_INDICATOR};

    #[test]
    fn fits_without_allocation() {
        let mut buf = FixedString::<8>::new();
        buf.set_truncated("short", TRUNCATION_INDICATOR);
        assert_eq!(buf.as_str(), "short");
    }

    #[test]
    fn truncates_on_utf8_boundary() {
        let mut buf = FixedString::<17>::new();
        buf.set_truncated(&"🔥".repeat(16), TRUNCATION_INDICATOR);
        assert!(std::str::from_utf8(buf.as_str().as_bytes()).is_ok());
        assert!(buf.len() <= 17);
    }

    #[test]
    fn duplicate_copies_contents() {
        let mut original = FixedString::<16>::new();
        original.set_truncated("payload", TRUNCATION_INDICATOR);
        let duplicate = original.duplicate();
        assert_eq!(duplicate.as_str(), "payload");
    }
}
