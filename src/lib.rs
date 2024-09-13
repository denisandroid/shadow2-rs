//! This modules provides a wrapper around the libc functions in `shadow.h` for
//! handling the `/etc/shadow` file, which stores encrypted password for users.
//!
//! It should work under Linux and some other Unix variants. Root permission is
//! necessary to access the shadow file.
//!
//! Since the relevant functions in libc are not thread-safe, this library is
//! not either.
//!
//! # Examples
//!
//! Print all shadow entries:
//!
//! ```
//! use shadow::Shadow;
//!
//! for i in Shadow::iter_all() {
//!     println!("{:?}", i);
//! }
//! ```
//!
//! Verify password is correct (requires
//! [pwhash](https://crates.io/crates/pwhash)):
//!
//! ```
//! use shadow::Shadow;
//! use pwhash::unix::verify;
//!
//! let hash = Shadow::from_name("username").unwrap();
//! let correct = verify("password", &hash.password);
//! println!("Password correct: {}", correct); 
//! ```


extern crate libc;


use std::ffi::CString;
use std::ffi::CStr;
use libc::c_long;

/*
#UlinProject24, fix:
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:63:26
   |
63 |             last_change: (*spwd).sp_lstchg,
   |                          ^^^^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:64:18
   |
64 |             min: (*spwd).sp_min,
   |                  ^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:65:18
   |
65 |             max: (*spwd).sp_max,
   |                  ^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:66:19
   |
66 |             warn: (*spwd).sp_warn,
   |                   ^^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:67:23
   |
67 |             inactive: (*spwd).sp_inact,
   |                       ^^^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
error[E0308]: mismatched types
  --> /home/user/work/openwrt/dl/cargo/registry/src/index.crates.io-6f17d22bba15001f/shadow-0.0.1/src/lib.rs:68:21
   |
68 |             expire: (*spwd).sp_expire,
   |                     ^^^^^^^^^^^^^^^^^ expected `i64`, found `i32`
 
For more information about this error, try `rustc --explain E0308`.
error: could not compile `shadow` (lib) due to 6 previous errors
*/

/// Represents an entry in `/etc/shadow`
#[derive(Debug)]
pub struct Shadow {
    /// user login name
    pub name: String,
    /// encrypted password
    pub password: String,
    /// last password change
    pub last_change: c_long,
    /// days until change allowed
    pub min: c_long,
    /// days before change required
    pub max: c_long,
    /// days warning for expiration
    pub warn: c_long,
    /// days before account inactive
    pub inactive: c_long,
    /// date when account expires
    pub expire: c_long,
}

impl Shadow {
    unsafe fn from_ptr(spwd: *const libc::spwd) -> Shadow {
        Shadow {
            name: CStr::from_ptr((*spwd).sp_namp).to_str().unwrap().to_owned(),
            password: CStr::from_ptr((*spwd).sp_pwdp).to_str().unwrap().to_owned(),
            last_change: (*spwd).sp_lstchg,
            min: (*spwd).sp_min,
            max: (*spwd).sp_max,
            warn: (*spwd).sp_warn,
            inactive: (*spwd).sp_inact,
            expire: (*spwd).sp_expire,
        }
    }

    /// Gets a `Shadow` entry for the given username, or returns `None`
    pub fn from_name(user: &str) -> Option<Shadow> {
        let c_user = CString::new(user).unwrap();

        let spwd = unsafe { libc::getspnam(c_user.as_ptr()) };

        if spwd.is_null() {
            None
        } else {
            Some(unsafe { Shadow::from_ptr(spwd) })
        }
    }

    /// Returns iterator over all entries in `shadow` file
    pub fn iter_all() -> ShadowIter {
        ShadowIter::default()
    }
}

/// Iterator over `Shadow` entries
#[derive(Default)]
pub struct ShadowIter {
    started: bool,
    done: bool,
}

impl Iterator for ShadowIter {
    type Item = Shadow;

    fn next(&mut self) -> Option<Shadow> {
        self.started = true;
        if !self.done {
            let spwd = unsafe { libc::getspent() };
            if spwd.is_null() {
                unsafe { libc::endspent() };
                self.done = true;
                None
            } else {
                Some(unsafe { Shadow::from_ptr(spwd) })
            }
        } else {
            None
        }
    }
}

impl Drop for ShadowIter {
    fn drop(&mut self) {
        if self.started && !self.done {
            unsafe { libc::endspent() };
        }
    }
}
