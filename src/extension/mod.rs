//! Implements an extension to mercurial signature - Mercurial Signature with Variable-Length Messages.

pub mod public_key;
pub use public_key::PublicKey;

pub mod secret_key;
pub use secret_key::SecretKey;

pub mod representation;
pub use representation::change_representation;

pub mod signature;
