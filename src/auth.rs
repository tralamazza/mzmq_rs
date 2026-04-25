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

#[cfg(test)]
mod tests {
    use super::AuthCheck;

    #[test]
    fn unit_impl_always_returns_false() {
        assert!(!().check(b"user", b"pass"));
        assert!(!().check(b"", b""));
    }
}
