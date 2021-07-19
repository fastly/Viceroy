use super::{FastlyConfig, LocalServerConfig, RawLocalServerConfig};

#[test]
fn fastly_toml_files_can_be_read() {
    // Parse a valid `fastly.toml`, check that it succeeds.
    let config = FastlyConfig::from_str(
        r#"
        name = "simple-toml-example"
        description = "a simple toml example"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
    "#,
    )
    .expect("can read toml data");

    // Check that the name, description, authors, and language fields were parsed correctly.
    assert_eq!(config.name(), "simple-toml-example");
    assert_eq!(config.description(), "a simple toml example");
    assert_eq!(
        config.authors(),
        [
            "Jill Bryson <jbryson@fastly.com>",
            "Rose McDowall <rmcdowall@fastly.com>"
        ]
    );
    assert_eq!(config.language(), "rust");
}

/// Show that we can successfully parse a `fastly.toml` with backend configurations.
///
/// This provides an example `fastly.toml` file including a `#[testing.backends]` section. This
/// includes various backend definitions, that may or may not include an environment key.
#[test]
fn fastly_toml_files_with_simple_backend_configurations_can_be_read() {
    let config = FastlyConfig::from_str(
        r#"
            manifest_version = "1.2.3"
            name = "backend-config-example"
            description = "a toml example with backend configuration"
            authors = [
                "Amelia Watson <awatson@fastly.com>",
                "Inugami Korone <kinugami@fastly.com>",
            ]
            language = "rust"

            [local_server]
              [local_server.backends]
                [local_server.backends.dog]
                url = "http://localhost:7878/dog-mocks"
  
                [local_server.backends."shark.server"]
                url = "http://localhost:7878/shark-mocks"
                override_host = "somehost.com"

                [local_server.backends.detective]
                url = "http://www.elementary.org/"
    "#,
    )
    .expect("can read toml data containing backend configurations");

    let backend = config
        .backends()
        .get("dog")
        .expect("backend configurations can be accessed");
    assert_eq!(backend.uri, "http://localhost:7878/dog-mocks");
    assert_eq!(backend.override_host, None);

    let backend = config
        .backends()
        .get("shark.server")
        .expect("backend configurations can be accessed");
    assert_eq!(backend.uri, "http://localhost:7878/shark-mocks");
    assert_eq!(
        backend.override_host,
        Some("somehost.com".parse().expect("can parse override_host"))
    );
}

/// Unit tests for the `testing` section of a `fastly.toml` package manifest.
///
/// In particular, these tests check that we deserialize and validate the backend configurations
/// section of the TOML data properly. In the interest of brevity, this section works with TOML data
/// that would be placed beneath the `testing` key, rather than an entire package manifest as in
/// the tests above.
mod testing_config_tests {
    use {
        super::{LocalServerConfig, RawLocalServerConfig},
        crate::error::{
            BackendConfigError,
            FastlyConfigError::{self, InvalidBackendDefinition},
        },
        std::convert::TryInto,
    };

    fn read_toml_config(toml: &str) -> Result<LocalServerConfig, FastlyConfigError> {
        toml::from_str::<'_, RawLocalServerConfig>(toml)
            .expect("valid toml data")
            .try_into()
    }

    /// Check that the `testing` section can be deserialized.
    // This case is technically redundant, but it is nice to have a unit test that demonstrates the
    // happy path for this group of unit tests.
    #[test]
    fn backend_configs_can_be_deserialized() {
        static BACKENDS: &str = r#"
            [backends]            
              [backends.dog]
              url = "http://localhost:7878/dog-mocks"
        "#;
        match read_toml_config(BACKENDS) {
            Ok(_) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that backend definitions must be given as TOML tables.
    #[test]
    fn backend_configs_must_use_toml_tables() {
        use BackendConfigError::InvalidEntryType;
        static BAD_DEF: &str = r#"
            [backends]
            "shark" = "https://a.com"
        "#;
        match read_toml_config(BAD_DEF) {
            Err(InvalidBackendDefinition {
                err: InvalidEntryType,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that backend definitions cannot contain unrecognized keys.
    #[test]
    fn backend_configs_cannot_contain_unrecognized_keys() {
        use BackendConfigError::UnrecognizedKey;
        static BAD_DEFAULT: &str = r#"
            [backends]
            shark = { url = "https://a.com", shrimp = true }
        "#;
        match read_toml_config(BAD_DEFAULT) {
            Err(InvalidBackendDefinition {
                err: UnrecognizedKey(key),
                ..
            }) if key == "shrimp" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that backend definitions *must* include a `url` field.
    #[test]
    fn backend_configs_must_provide_a_url() {
        use BackendConfigError::MissingUrl;
        static NO_URL: &str = r#"
            [backends]
            "shark" = {}
        "#;
        match read_toml_config(NO_URL) {
            Err(InvalidBackendDefinition {
                err: MissingUrl, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that backend definitions *must* include a `url` field.
    #[test]
    fn backend_configs_must_provide_urls_as_a_string() {
        use BackendConfigError::InvalidUrlEntry;
        static BAD_URL_FIELD: &str = r#"
            [backends]
            "shark" = { url = 3 }
        "#;
        match read_toml_config(BAD_URL_FIELD) {
            Err(InvalidBackendDefinition {
                err: InvalidUrlEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that backend definitions must include a *valid* `url` field.
    #[test]
    fn backend_configs_must_provide_a_valid_url() {
        use BackendConfigError::InvalidUrl;
        static BAD_URL_FIELD: &str = r#"
            [backends]
            "shark" = { url = "http:://[:::1]" }
        "#;
        match read_toml_config(BAD_URL_FIELD) {
            Err(InvalidBackendDefinition {
                err: InvalidUrl(_), ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that override_host field is a string.
    #[test]
    fn backend_configs_must_provide_override_host_as_a_string() {
        use BackendConfigError::InvalidOverrideHostEntry;
        static BAD_OVERRIDE_HOST_FIELD: &str = r#"
            [backends]
            "shark" = { url = "http://a.com", override_host = 3 }
        "#;
        match read_toml_config(BAD_OVERRIDE_HOST_FIELD) {
            Err(InvalidBackendDefinition {
                err: InvalidOverrideHostEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that override_host field is non empty.
    #[test]
    fn backend_configs_must_provide_a_non_empty_override_host() {
        use BackendConfigError::EmptyOverrideHost;
        static EMPTY_OVERRIDE_HOST_FIELD: &str = r#"
            [backends]
            "shark" = { url = "http://a.com", override_host = "" }
        "#;
        match read_toml_config(EMPTY_OVERRIDE_HOST_FIELD) {
            Err(InvalidBackendDefinition {
                err: EmptyOverrideHost,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that override_host field is valid.
    #[test]
    fn backend_configs_must_provide_a_valid_override_host() {
        use BackendConfigError::InvalidOverrideHost;
        static BAD_OVERRIDE_HOST_FIELD: &str = r#"
            [backends]
            "shark" = { url = "http://a.com", override_host = "somehost.com\n" }
        "#;
        match read_toml_config(BAD_OVERRIDE_HOST_FIELD) {
            Err(InvalidBackendDefinition {
                err: InvalidOverrideHost(_),
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}
