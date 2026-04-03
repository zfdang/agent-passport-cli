pub const DISPLAY_VERSION: &str = match option_env!("KITEPASS_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[cfg(test)]
mod tests {
    use super::DISPLAY_VERSION;

    #[test]
    fn display_version_starts_with_package_version() {
        assert!(DISPLAY_VERSION.starts_with(env!("CARGO_PKG_VERSION")));
    }
}
