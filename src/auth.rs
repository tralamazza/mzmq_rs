#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mechanism {
    Null,
    #[cfg(feature = "plain")]
    Plain,
}

pub trait AuthCheck {
    fn check(&self, username: &[u8], password: &[u8]) -> bool;
}

impl AuthCheck for () {
    fn check(&self, _username: &[u8], _password: &[u8]) -> bool {
        false
    }
}
