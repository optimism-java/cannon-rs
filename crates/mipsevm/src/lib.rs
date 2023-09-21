// #![doc = include_str!("../README.md")]
#![feature(generic_const_exprs)]
#![allow(incomplete_features, dead_code)]

mod memory;
pub use self::memory::{Address, Gindex, Memory, PageIndex};

mod page;
pub use self::page::{CachedPage, Page};

mod state;
mod traits;
mod utils;
