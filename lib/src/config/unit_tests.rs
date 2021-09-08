use crate::config::dictionaries::DictionaryFormat;

use {
    super::{FastlyConfig, LocalServerConfig, RawLocalServerConfig},
    crate::{config::DictionaryName, error::FastlyConfigError},
    std::{fs::File, io::Write},
    tempfile::tempdir,
};

#[test]
fn error_when_fastly_toml_files_cannot_be_read() {
    match FastlyConfig::from_file("nonexistent.toml") {
        Err(FastlyConfigError::IoError { path, .. }) if path == "nonexistent.toml" => {}
        res => panic!("unexpected result: {:?}", res),
    }
}

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
/// This provides an example `fastly.toml` file including a `#[local_server.backends]` section. This
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

/// Show that we can successfully parse a `fastly.toml` with local_server.dictionaries configurations.
///
/// This provides an example `fastly.toml` file including a `#[local_server.dictionaries]` section.
#[test]
fn fastly_toml_files_with_simple_dictionary_configurations_can_be_read() {
    let dir = tempdir().unwrap();

    let file_path = dir.path().join("a.json");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "{{}}").unwrap();
    let config = FastlyConfig::from_str(format!(
        r#"
            manifest_version = "1.2.3"
            name = "dictionary-config-example"
            description = "a toml example with dictionary configuration"
            authors = [
                "Amelia Watson <awatson@fastly.com>",
                "Inugami Korone <kinugami@fastly.com>",
            ]
            language = "rust"

            [local_server]
                [local_server.dictionaries]
                    [local_server.dictionaries.a]
                    file='{}'
                    format = "json"
    "#,
        &file_path.to_str().unwrap()
    ))
    .expect("can read toml data containing local dictionary configurations");

    let dictionary = config
        .dictionaries()
        .get(&DictionaryName::new("a".to_string()))
        .expect("dictionary configurations can be accessed");
    assert_eq!(dictionary.file, file_path);
    assert_eq!(dictionary.format, DictionaryFormat::Json);
}

/// Unit tests for the `local_server` section of a `fastly.toml` package manifest.
///
/// In particular, these tests check that we deserialize and validate the backend configurations
/// section of the TOML data properly. In the interest of brevity, this section works with TOML data
/// that would be placed beneath the `local_server` key, rather than an entire package manifest as in
/// the tests above.
mod local_server_config_tests {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use {
        super::{LocalServerConfig, RawLocalServerConfig},
        crate::error::{
            BackendConfigError, DictionaryConfigError,
            FastlyConfigError::{self, InvalidBackendDefinition, InvalidDictionaryDefinition},
        },
        std::convert::TryInto,
    };

    fn read_toml_config(toml: &str) -> Result<LocalServerConfig, FastlyConfigError> {
        toml::from_str::<'_, RawLocalServerConfig>(toml)
            .expect("valid toml data")
            .try_into()
    }

    /// Check that the `local_server` section can be deserialized.
    // This case is technically redundant, but it is nice to have a unit test that demonstrates the
    // happy path for this group of unit tests.
    #[test]
    fn local_server_configs_can_be_deserialized() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let local_server = format!(
            r#"
            [backends]            
              [backends.dog]
              url = "http://localhost:7878/dog-mocks"
            [dicionaries]            
              [dicionaries.secrets]
              file = '{}'
              format = "json"
        "#,
            file_path.to_str().unwrap()
        );
        match read_toml_config(&local_server) {
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

    /// Check that dictionary definitions must be given as TOML tables.
    #[test]
    fn dictionary_configs_must_use_toml_tables() {
        use DictionaryConfigError::InvalidEntryType;
        static BAD_DEF: &str = r#"
            [dictionaries]
            "thing" = "stuff"
        "#;
        match read_toml_config(BAD_DEF) {
            Err(InvalidDictionaryDefinition {
                err: InvalidEntryType,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that dictionary definitions cannot contain unrecognized keys.
    #[test]
    fn dictionary_configs_cannot_contain_unrecognized_keys() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        use DictionaryConfigError::UnrecognizedKey;
        let bad_default = format!(
            r#"
            [dictionaries]
            thing = {{ file = '{}', format = "json", shrimp = true }}
        "#,
            file_path.to_str().unwrap()
        );
        match read_toml_config(&bad_default) {
            Err(InvalidDictionaryDefinition {
                err: UnrecognizedKey(key),
                ..
            }) if key == "shrimp" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that dictionary definitions *must* include a `file` field.
    #[test]
    fn dictionary_configs_must_provide_a_file() {
        use DictionaryConfigError::MissingFile;
        static NO_FILE: &str = r#"
            [dictionaries]
            thing = {format = "json"}
        "#;
        match read_toml_config(NO_FILE) {
            Err(InvalidDictionaryDefinition {
                err: MissingFile, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that dictionary definitions *must* include a `format` field.
    #[test]
    fn dictionary_configs_must_provide_a_format() {
        use DictionaryConfigError::MissingFormat;
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let no_format_field = format!(
            r#"
            [dictionaries]
            "thing" = {{ file = '{}' }}
        "#,
            file_path.to_str().unwrap()
        );
        match read_toml_config(&no_format_field) {
            Err(InvalidDictionaryDefinition {
                err: MissingFormat, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that dictionary definitions must include a *valid* `name` field.
    #[test]
    fn dictionary_configs_must_provide_a_valid_name() {
        use DictionaryConfigError::InvalidName;
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let bad_name_field = format!(
            r#"
            [dictionaries]
            "1" = {{ file = '{}', format = "json" }}
        "#,
            file_path.to_str().unwrap()
        );
        match read_toml_config(&bad_name_field) {
            Err(InvalidDictionaryDefinition {
                err: InvalidName(_),
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that file field is a string.
    #[test]
    fn dictionary_configs_must_provide_file_as_a_string() {
        use DictionaryConfigError::InvalidFileEntry;
        static BAD_FILE_FIELD: &str = r#"
            [dictionaries]
            "thing" = { file = 3, format = "json" }
        "#;
        match read_toml_config(BAD_FILE_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: InvalidFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that file field is non empty.
    #[test]
    fn dictionary_configs_must_provide_a_non_empty_file() {
        use DictionaryConfigError::EmptyFileEntry;
        static EMPTY_FILE_FIELD: &str = r#"
            [dictionaries]
            "thing" = { file = "", format = "json" }
        "#;
        match read_toml_config(EMPTY_FILE_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: EmptyFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that format field is a string.
    #[test]
    fn dictionary_configs_must_provide_format_as_a_string() {
        use DictionaryConfigError::InvalidFormatEntry;
        static BAD_FORMAT_FIELD: &str = r#"
            [dictionaries]
            "thing" = { format = 3}
        "#;
        match read_toml_config(BAD_FORMAT_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: InvalidFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that format field is non empty.
    #[test]
    fn dictionary_configs_must_provide_a_non_empty_format() {
        use DictionaryConfigError::EmptyFormatEntry;
        static EMPTY_FORMAT_FIELD: &str = r#"
            [dictionaries]
            "thing" = { format = "" }
        "#;
        match read_toml_config(EMPTY_FORMAT_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: EmptyFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
    /// Check that format field set to json is valid.
    #[test]
    fn valid_dictionary_config_with_format_set_to_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let dictionary = format!(
            r#"
            [dictionaries]
            "thing" = {{ file = '{}', format = "json" }}
        "#,
            file_path.to_str().unwrap()
        );
        read_toml_config(&dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }
}
