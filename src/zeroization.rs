//! Local zeroization primitives.
//!
//! The crate avoids an external zeroization dependency by keeping the
//! byte-clearing logic here and routing all sensitive-memory cleanup through
//! this module.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};

/// Trait for types that can scrub their sensitive contents in place.
pub(crate) trait Zeroize {
    /// Overwrite the sensitive contents of `self`.
    fn zeroize(&mut self);
}

/// Execute `Zeroize::zeroize` and suppress any panic during drop cleanup.
#[inline]
pub(crate) fn drop_zeroize<T>(value: &mut T)
where
    T: Zeroize + ?Sized,
{
    let _ = catch_unwind(AssertUnwindSafe(|| value.zeroize()));
}

/// Overwrite a raw byte region using volatile stores.
#[inline(never)]
pub(crate) unsafe fn zeroize_raw(ptr: *mut u8, len: usize) {
    for index in 0..len {
        // SAFETY: The caller guarantees that `ptr..ptr+len` is a valid,
        // writable region for the lifetime of this call.
        unsafe {
            ptr::write_volatile(ptr.add(index), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrite a mutable byte slice using volatile stores.
#[inline(never)]
pub(crate) fn zeroize_bytes(bytes: &mut [u8]) {
    // SAFETY: `bytes` is a valid writable region owned by the caller.
    unsafe {
        zeroize_raw(bytes.as_mut_ptr(), bytes.len());
    }
}

/// Overwrite a `String`'s backing buffer and then clear its visible length.
#[inline(never)]
pub(crate) fn zeroize_string(s: &mut String) {
    // SAFETY: `String` guarantees its pointer is valid for `len` writable bytes.
    unsafe {
        zeroize_raw(s.as_mut_ptr(), s.len());
    }
    s.clear();
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        zeroize_string(self);
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        zeroize_bytes(self.as_mut_slice());
        self.clear();
    }
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        zeroize_bytes(self);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        zeroize_bytes(self.as_mut_slice());
    }
}

impl Zeroize for u8 {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid writable byte for the duration of the call.
        unsafe {
            ptr::write_volatile(self, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::Zeroize;

    #[test]
    fn string_zeroize_clears_length() {
        let mut value = String::from("sensitive");
        value.zeroize();
        assert!(value.is_empty());
    }

    #[test]
    fn array_zeroize_clears_bytes() {
        let mut value = [0xAB_u8; 8];
        value.zeroize();
        assert_eq!(value, [0u8; 8]);
    }
}
