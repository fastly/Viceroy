use {
    super::{FastlyConfig, LocalServerConfig, RawLocalServerConfig},
    crate::error::FastlyConfigError,
    std::{convert::TryInto, fs::File, io::Write},
    tempfile::tempdir,
};

/// A test helper used to read the `local_server` section of a config file.
///
/// In the interest of brevity, this section works with TOML data that would be placed beneath the
/// `local_server` key, rather than an entire package manifest as in the tests above.
fn read_local_server_config(toml: &str) -> Result<LocalServerConfig, FastlyConfigError> {
    toml::from_str::<'_, RawLocalServerConfig>(toml)
        .expect("valid toml data")
        .try_into()
}

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
                url = "http://localhost:7676/dog-mocks"

                [local_server.backends."shark.server"]
                url = "http://localhost:7676/shark-mocks"
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
    assert_eq!(backend.uri, "http://localhost:7676/dog-mocks");
    assert_eq!(backend.override_host, None);

    let backend = config
        .backends()
        .get("shark.server")
        .expect("backend configurations can be accessed");
    assert_eq!(backend.uri, "http://localhost:7676/shark-mocks");
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
        .get("a")
        .expect("dictionary configurations can be accessed");
    assert_eq!(dictionary.file_path().unwrap(), file_path);
    assert!(dictionary.is_json());
}

/// Show that we can successfully parse a `fastly.toml` with local_server.config_stores configurations.
///
/// This provides an example `fastly.toml` file including a `#[local_server.config_stores]` section.
#[test]
fn fastly_toml_files_with_simple_config_store_configurations_can_be_read() {
    let dir = tempdir().unwrap();

    let file_path = dir.path().join("a.json");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "{{}}").unwrap();
    let config = FastlyConfig::from_str(format!(
        r#"
            manifest_version = "1.2.3"
            name = "dictionary-config-example"
            description = "a toml example with config store configuration"
            authors = [
                "Amelia Watson <awatson@fastly.com>",
                "Inugami Korone <kinugami@fastly.com>",
            ]
            language = "rust"

            [local_server]
                [local_server.config_stores]
                    [local_server.config_stores.a]
                    file='{}'
                    format = "json"
    "#,
        &file_path.to_str().unwrap()
    ))
    .expect("can read toml data containing local dictionary configurations");

    let dictionary = config
        .dictionaries()
        .get("a")
        .expect("dictionary configurations can be accessed");
    assert_eq!(dictionary.file_path().unwrap(), file_path);
    assert!(dictionary.is_json());
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
          url = "http://localhost:7676/dog-mocks"
        [dictionaries]
          [dictionaries.secrets]
          file = '{}'
          format = "json"
    "#,
        file_path.to_str().unwrap()
    );
    match read_local_server_config(&local_server) {
        Ok(_) => {}
        res => panic!("unexpected result: {:?}", res),
    }
}

/// Unit tests for backends in the `local_server` section of a `fastly.toml` package manifest.
///
/// In particular, these tests check that we deserialize and validate the backend configurations
/// section of the TOML data properly.
mod backend_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{BackendConfigError, FastlyConfigError::InvalidBackendDefinition},
    };

    /// Check that backend definitions must be given as TOML tables.
    #[test]
    fn backend_configs_must_use_toml_tables() {
        use BackendConfigError::InvalidEntryType;
        static BAD_DEF: &str = r#"
            [backends]
            "shark" = "https://a.com"
        "#;
        match read_local_server_config(BAD_DEF) {
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
        match read_local_server_config(BAD_DEFAULT) {
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
        match read_local_server_config(NO_URL) {
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
        match read_local_server_config(BAD_URL_FIELD) {
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
        match read_local_server_config(BAD_URL_FIELD) {
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
        match read_local_server_config(BAD_OVERRIDE_HOST_FIELD) {
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
        match read_local_server_config(EMPTY_OVERRIDE_HOST_FIELD) {
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
        match read_local_server_config(BAD_OVERRIDE_HOST_FIELD) {
            Err(InvalidBackendDefinition {
                err: InvalidOverrideHost(_),
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

/// Unit tests for dictionaries/config_stores in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the dictionary configurations section of
/// the TOML data properly regardless of the format.
mod dictionary_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{DictionaryConfigError, FastlyConfigError::InvalidDictionaryDefinition},
    };

    /// Check that dictionary definitions have a valid `format`.
    #[test]
    fn dictionary_configs_have_a_valid_format() {
        use DictionaryConfigError::InvalidDictionaryFormat;
        let invalid_format_field = r#"
            [dictionaries.a]
            format = "foo"
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        match read_local_server_config(invalid_format_field) {
            Err(InvalidDictionaryDefinition {
                err: InvalidDictionaryFormat(format),
                ..
            }) if format == "foo" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions have a valid `format`.
    #[test]
    fn config_store_configs_have_a_valid_format() {
        use DictionaryConfigError::InvalidDictionaryFormat;
        let invalid_format_field = r#"
            [config_stores.a]
            format = "foo"
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        match read_local_server_config(invalid_format_field) {
            Err(InvalidDictionaryDefinition {
                err: InvalidDictionaryFormat(format),
                ..
            }) if format == "foo" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

/// Unit tests for dictionaries/config-stores in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the dictionary/config-store configurations section of
/// the TOML data properly for dictionaries/config-stores using JSON files to store their data.
mod json_dictionary_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{DictionaryConfigError, FastlyConfigError::InvalidDictionaryDefinition},
        std::{fs::File, io::Write},
        tempfile::tempdir,
    };

    /// Check that dictionary definitions must be given as TOML tables.
    #[test]
    fn dictionary_configs_must_use_toml_tables() {
        use DictionaryConfigError::InvalidEntryType;
        static BAD_DEF: &str = r#"
            [dictionaries]
            "thing" = "stuff"
        "#;
        match read_local_server_config(BAD_DEF) {
            Err(InvalidDictionaryDefinition {
                err: InvalidEntryType,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions must be given as TOML tables.
    #[test]
    fn config_store_configs_must_use_toml_tables() {
        use DictionaryConfigError::InvalidEntryType;
        static BAD_DEF: &str = r#"
            [config_stores]
            "thing" = "stuff"
        "#;
        match read_local_server_config(BAD_DEF) {
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
        match read_local_server_config(&bad_default) {
            Err(InvalidDictionaryDefinition {
                err: UnrecognizedKey(key),
                ..
            }) if key == "shrimp" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions cannot contain unrecognized keys.
    #[test]
    fn config_store_configs_cannot_contain_unrecognized_keys() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        use DictionaryConfigError::UnrecognizedKey;
        let bad_default = format!(
            r#"
            [config_stores]
            thing = {{ file = '{}', format = "json", shrimp = true }}
        "#,
            file_path.to_str().unwrap()
        );
        match read_local_server_config(&bad_default) {
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
        match read_local_server_config(NO_FILE) {
            Err(InvalidDictionaryDefinition {
                err: MissingFile, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions *must* include a `file` field.
    #[test]
    fn config_store_configs_must_provide_a_file() {
        use DictionaryConfigError::MissingFile;
        static NO_FILE: &str = r#"
            [config_stores]
            thing = {format = "json"}
        "#;
        match read_local_server_config(NO_FILE) {
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
        match read_local_server_config(&no_format_field) {
            Err(InvalidDictionaryDefinition {
                err: MissingFormat, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions *must* include a `format` field.
    #[test]
    fn config_store_configs_must_provide_a_format() {
        use DictionaryConfigError::MissingFormat;
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let no_format_field = format!(
            r#"
            [config_stores]
            "thing" = {{ file = '{}' }}
        "#,
            file_path.to_str().unwrap()
        );
        match read_local_server_config(&no_format_field) {
            Err(InvalidDictionaryDefinition {
                err: MissingFormat, ..
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
        match read_local_server_config(BAD_FILE_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: InvalidFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that file field is a string.
    #[test]
    fn config_store_configs_must_provide_file_as_a_string() {
        use DictionaryConfigError::InvalidFileEntry;
        static BAD_FILE_FIELD: &str = r#"
            [config_stores]
            "thing" = { file = 3, format = "json" }
        "#;
        match read_local_server_config(BAD_FILE_FIELD) {
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
        match read_local_server_config(EMPTY_FILE_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: EmptyFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that file field is non empty.
    #[test]
    fn config_store_configs_must_provide_a_non_empty_file() {
        use DictionaryConfigError::EmptyFileEntry;
        static EMPTY_FILE_FIELD: &str = r#"
            [config_stores]
            "thing" = { file = "", format = "json" }
        "#;
        match read_local_server_config(EMPTY_FILE_FIELD) {
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
        match read_local_server_config(BAD_FORMAT_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: InvalidFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that format field is a string.
    #[test]
    fn config_store_configs_must_provide_format_as_a_string() {
        use DictionaryConfigError::InvalidFormatEntry;
        static BAD_FORMAT_FIELD: &str = r#"
            [config_stores]
            "thing" = { format = 3}
        "#;
        match read_local_server_config(BAD_FORMAT_FIELD) {
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
        match read_local_server_config(EMPTY_FORMAT_FIELD) {
            Err(InvalidDictionaryDefinition {
                err: EmptyFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that format field is non empty.
    #[test]
    fn config_store_configs_must_provide_a_non_empty_format() {
        use DictionaryConfigError::EmptyFormatEntry;
        static EMPTY_FORMAT_FIELD: &str = r#"
            [config_stores]
            "thing" = { format = "" }
        "#;
        match read_local_server_config(EMPTY_FORMAT_FIELD) {
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
        read_local_server_config(&dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }

    /// Check that format field set to json is valid.
    #[test]
    fn valid_config_store_config_with_format_set_to_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("secrets.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let dictionary = format!(
            r#"
            [config_stores]
            "thing" = {{ file = '{}', format = "json" }}
        "#,
            file_path.to_str().unwrap()
        );
        read_local_server_config(&dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }
}

/// Unit tests for dictionaries/config_stores in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the dictionary configurations section of
/// the TOML data properly for dictionaries/config_stores using inline TOML to store their data.
mod inline_toml_dictionary_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{DictionaryConfigError, FastlyConfigError::InvalidDictionaryDefinition},
    };

    #[test]
    fn valid_inline_toml_dictionaries_can_be_parsed() {
        let dictionary = r#"
            [dictionaries.inline_toml_example]
            format = "inline-toml"
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        read_local_server_config(dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }

    #[test]
    fn valid_inline_toml_config_stores_can_be_parsed() {
        let dictionary = r#"
            [config_stores.inline_toml_example]
            format = "inline-toml"
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        read_local_server_config(dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }

    /// Check that dictionary definitions *must* include a `format` field.
    #[test]
    fn dictionary_configs_must_provide_a_format() {
        use DictionaryConfigError::MissingFormat;
        let no_format_field = r#"
            [dictionaries.missing_format]
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        match read_local_server_config(no_format_field) {
            Err(InvalidDictionaryDefinition {
                err: MissingFormat, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions *must* include a `format` field.
    #[test]
    fn config_store_configs_must_provide_a_format() {
        use DictionaryConfigError::MissingFormat;
        let no_format_field = r#"
            [config_stores.missing_format]
            contents = { apple = "fruit", potato = "vegetable" }
        "#;
        match read_local_server_config(no_format_field) {
            Err(InvalidDictionaryDefinition {
                err: MissingFormat, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that dictionary definitions *must* include a `contents` field.
    #[test]
    fn dictionary_configs_must_provide_contents() {
        use DictionaryConfigError::MissingContents;
        let missing_contents = r#"
            [dictionaries.missing_contents]
            format = "inline-toml"
        "#;
        match read_local_server_config(missing_contents) {
            Err(InvalidDictionaryDefinition {
                err: MissingContents,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that config_store definitions *must* include a `contents` field.
    #[test]
    fn config_store_configs_must_provide_contents() {
        use DictionaryConfigError::MissingContents;
        let missing_contents = r#"
            [config_stores.missing_contents]
            format = "inline-toml"
        "#;
        match read_local_server_config(missing_contents) {
            Err(InvalidDictionaryDefinition {
                err: MissingContents,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

/// Unit tests for Device Detection mapping in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the Device Detection mappings section of
/// the TOML data properly regardless of the format.
mod device_detection_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{
            DeviceDetectionConfigError, FastlyConfigError::InvalidDeviceDetectionDefinition,
        },
    };

    /// Check that Device Detection definitions have a valid `format`.
    #[test]
    fn device_detection_has_a_valid_format() {
        use DeviceDetectionConfigError::InvalidDeviceDetectionMappingFormat;
        let invalid_format_field = r#"
            [device_detection]
            format = "foo"
            [device_detection.user_agent."Test User-Agent"]
            hwtype = "Test"
        "#;
        match read_local_server_config(invalid_format_field) {
            Err(InvalidDeviceDetectionDefinition {
                err: InvalidDeviceDetectionMappingFormat(format),
                ..
            }) if format == "foo" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

/// Unit tests for Geolocation mapping in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the Geolocation mappings section of
/// the TOML data properly regardless of the format.
mod geolocation_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{FastlyConfigError::InvalidGeolocationDefinition, GeolocationConfigError},
    };

    /// Check that Geolocation definitions have a valid `format`.
    #[test]
    fn geolocation_has_a_valid_format() {
        use GeolocationConfigError::InvalidGeolocationMappingFormat;
        let invalid_format_field = r#"
            [geolocation]
            format = "foo"
            [geolocation.addresses."123.45.67.89"]
            as_name = "Test, Inc."
        "#;
        match read_local_server_config(invalid_format_field) {
            Err(InvalidGeolocationDefinition {
                err: InvalidGeolocationMappingFormat(format),
                ..
            }) if format == "foo" => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

/// Unit tests for Geolocation mapping in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the dictionary configurations section of
/// the TOML data properly for Geolocation mapping using JSON files to store their data.
mod json_geolocation_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{FastlyConfigError::InvalidGeolocationDefinition, GeolocationConfigError},
        std::{fs::File, io::Write},
        tempfile::tempdir,
    };

    /// Check that Geolocation mapping *must* include a `file` field.
    #[test]
    fn geolocation_must_provide_a_file() {
        use GeolocationConfigError::MissingFile;
        static NO_FILE: &str = r#"
            [geolocation]
            format = "json"
        "#;
        match read_local_server_config(NO_FILE) {
            Err(InvalidGeolocationDefinition {
                err: MissingFile, ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that file field is a string.
    #[test]
    fn geolocation_must_provide_file_as_a_string() {
        use GeolocationConfigError::InvalidFileEntry;
        static BAD_FILE_FIELD: &str = r#"
            [geolocation]
            file = 3
            format = "json"
        "#;
        match read_local_server_config(BAD_FILE_FIELD) {
            Err(InvalidGeolocationDefinition {
                err: InvalidFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that file field is non empty.
    #[test]
    fn geolocation_must_provide_a_non_empty_file() {
        use GeolocationConfigError::EmptyFileEntry;
        static EMPTY_FILE_FIELD: &str = r#"
            [geolocation]
            file = ""
            format = "json"
        "#;
        match read_local_server_config(EMPTY_FILE_FIELD) {
            Err(InvalidGeolocationDefinition {
                err: EmptyFileEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that format field is a string.
    #[test]
    fn geolocation_must_provide_format_as_a_string() {
        use GeolocationConfigError::InvalidFormatEntry;
        static BAD_FORMAT_FIELD: &str = r#"
            [geolocation]
            format = 3
        "#;
        match read_local_server_config(BAD_FORMAT_FIELD) {
            Err(InvalidGeolocationDefinition {
                err: InvalidFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that format field is non empty.
    #[test]
    fn geolocation_must_provide_a_non_empty_format() {
        use GeolocationConfigError::EmptyFormatEntry;
        static EMPTY_FORMAT_FIELD: &str = r#"
            [geolocation]
            format = ""
        "#;
        match read_local_server_config(EMPTY_FORMAT_FIELD) {
            Err(InvalidGeolocationDefinition {
                err: EmptyFormatEntry,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Check that format field set to json is valid.
    #[test]
    fn valid_geolocation_with_format_set_to_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("mapping.json");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{{}}").unwrap();

        let dictionary = format!(
            r#"
            [geolocation]
            file = '{}'
            format = "json"
        "#,
            file_path.to_str().unwrap()
        );
        read_local_server_config(&dictionary).expect(
            "can read toml data containing local dictionary configurations using json format",
        );
    }
}

/// Unit tests for Geolocation mapping in the `local_server` section of a `fastly.toml` package manifest.
///
/// These tests check that we deserialize and validate the dictionary configurations section of
/// the TOML data properly for Geolocation mapping using inline TOML to store their data.
mod inline_toml_geolocation_config_tests {
    use {
        super::read_local_server_config,
        crate::error::{FastlyConfigError::InvalidGeolocationDefinition, GeolocationConfigError},
    };

    #[test]
    fn valid_inline_toml_geolocation_can_be_parsed() {
        let geolocation = r#"
            [geolocation]
            format = "inline-toml"
            [geolocation.addresses]
            [geolocation.addresses."127.0.0.1"]
            as_name = "Test, Inc."
        "#;
        read_local_server_config(geolocation)
            .expect("can read toml data containing local Geolocation mappings using toml format");
    }

    /// Check that Geolocation mapping *must* include a `contents` field.
    #[test]
    fn geolocation_must_provide_contents() {
        use GeolocationConfigError::MissingAddresses;
        let missing_contents = r#"
            [geolocation]
            format = "inline-toml"
        "#;
        match read_local_server_config(missing_contents) {
            Err(InvalidGeolocationDefinition {
                err: MissingAddresses,
                ..
            }) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }
}

mod ca_cert_config_tests {
    use super::read_local_server_config;

    #[test]
    fn ca_certs_default_to_empty() {
        let standard_backend = r#"
            [backends]
            [backends.dog]
            url = "http://localhost:7676/dog-mocks"
        "#;

        let basic = read_local_server_config(standard_backend).expect("can parse basic config");
        let dog_backend = basic.backends.0.get("dog").expect("fetch failed :(");
        assert!(dog_backend.ca_certs.is_empty());
    }

    #[test]
    fn reads_ca_certs() {
        let ca_backend = r#"
[backends]
[backends.dog]
url = "http://localhost:7676/dog-mocks"

[backends."shark.server"]
url = "http://localhost:7676/shark-mocks"
override_host = "somehost.com"
ca_certificate = '''
-----BEGIN CERTIFICATE-----
MIIDqTCCApGgAwIBAgIUDXDr/2fouphqlB8iJASenWOr/XwwDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEDAOBgNVBAoMB1ZpY2Vyb3kxHzAdBgkqhkiG9w0BCQEWEGF3aWNrQGZh
c3RseS5jb20wHhcNMjMwNzI3MDAwODU5WhcNMzMwNzI0MDAwODU5WjBkMQswCQYD
VQQGEwJVUzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEQMA4G
A1UECgwHVmljZXJveTEfMB0GCSqGSIb3DQEJARYQYXdpY2tAZmFzdGx5LmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxXdG4C6yEeLTtFPOXWTv1N
eEeJMLcAoupB9u3x0PYT+w+0ruAympviqGbEiyZL/qMKLYenLiQO+72VCISW5qfB
ZoCpwDxBon5TDUZ98JU93nVRml7uOg25G+KTs3aeJt6+rFDPNaNyxVcKgCuURB4y
mwgosLUvxoEffFnHlURETLN4aSGQ6TLp8YEJp4EudTVo/l+kdhm6sLZMBkmUxnnl
muEc8ePAr1igYchz2tbcWRjzxoUOuEdoKaW2OCElNObt2WYPWzHs+6p1K8+KyTRY
/pVOFtA43nuWmk++UHFthBAw9IqBuO0FMJr4SULnKfiTh5E9F+nZ0Q/1nfzzsAMC
AwEAAaNTMFEwHQYDVR0OBBYEFGYM6HhP8yZ17eXw5nOfQ971u1l9MB8GA1UdIwQY
MBaAFGYM6HhP8yZ17eXw5nOfQ971u1l9MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAFmFkUodKTXeT683GEj4SoiMbDL8d3x+Vc+kvLPC2Jloru4R
Qo0USu3eJZjNxKjmPbLii8gzf5ZmZHdytWQ+5irYjXBHrE9tPgmpavhM+0otpnUd
vYosnfwv/aQEIiqeMkpqzbSKvb2I+TVpAC1xb6qbYE95tnsX/KEdAoJ/SAcZLGYQ
LKGTjz3eKlgUWy69uwzHXkie8hxDVRlyA7cFY4AAqsLhL2KQPWtMT7fRKrVKfLYd
Qq7tJAMLnPnAdAUousI0RDcLpB8adGkhZH66lL4oV9U+aQ0dA0oiqSKZtMoHeWbr
/L0ti7ZOfxOxRRCzt8KdLo/kGNTfAz+74P0MY80=
-----END CERTIFICATE-----
'''
"#;

        let with_ca = read_local_server_config(ca_backend).expect("can parse backends with ca");
        let dog_backend = with_ca.backends.0.get("dog").expect("fetch failed :(");
        assert!(dog_backend.ca_certs.is_empty());
        let shark_backend = with_ca
            .backends
            .0
            .get("shark.server")
            .expect("no blåhaj :(");
        assert!(!shark_backend.ca_certs.is_empty());
    }

    #[test]
    fn reads_file_path_ca_certs() {
        let ca_backend = format!(
            r#"
[backends]
[backends.dog]
url = "http://localhost:7676/dog-mocks"

[backends."shark.server"]
url = "http://localhost:7676/shark-mocks"
override_host = "somehost.com"
ca_certificate.file = {:?}
"#,
            concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/data/ca.pem")
        );

        let with_ca = read_local_server_config(&ca_backend).expect("can parse backends with ca");
        let dog_backend = with_ca.backends.0.get("dog").expect("fetch failed :(");
        assert!(dog_backend.ca_certs.is_empty());
        let shark_backend = with_ca
            .backends
            .0
            .get("shark.server")
            .expect("no blåhaj :(");
        assert!(!shark_backend.ca_certs.is_empty());
    }

    #[test]
    fn reads_multiple_ca_certs() {
        let ca_backend = format!(
            r#"
[backends]
[backends.dog]
url = "http://localhost:7676/dog-mocks"

[backends."shark.server"]
url = "http://localhost:7676/shark-mocks"
override_host = "somehost.com"
[[backends."shark.server".ca_certificate]]
file = {:?}
[[backends."shark.server".ca_certificate]]
file = {:?}
[[backends."shark.server".ca_certificate]]
value = '''
-----BEGIN CERTIFICATE-----
MIIDqTCCApGgAwIBAgIUDXDr/2fouphqlB8iJASenWOr/XwwDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEDAOBgNVBAoMB1ZpY2Vyb3kxHzAdBgkqhkiG9w0BCQEWEGF3aWNrQGZh
c3RseS5jb20wHhcNMjMwNzI3MDAwODU5WhcNMzMwNzI0MDAwODU5WjBkMQswCQYD
VQQGEwJVUzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEQMA4G
A1UECgwHVmljZXJveTEfMB0GCSqGSIb3DQEJARYQYXdpY2tAZmFzdGx5LmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxXdG4C6yEeLTtFPOXWTv1N
eEeJMLcAoupB9u3x0PYT+w+0ruAympviqGbEiyZL/qMKLYenLiQO+72VCISW5qfB
ZoCpwDxBon5TDUZ98JU93nVRml7uOg25G+KTs3aeJt6+rFDPNaNyxVcKgCuURB4y
mwgosLUvxoEffFnHlURETLN4aSGQ6TLp8YEJp4EudTVo/l+kdhm6sLZMBkmUxnnl
muEc8ePAr1igYchz2tbcWRjzxoUOuEdoKaW2OCElNObt2WYPWzHs+6p1K8+KyTRY
/pVOFtA43nuWmk++UHFthBAw9IqBuO0FMJr4SULnKfiTh5E9F+nZ0Q/1nfzzsAMC
AwEAAaNTMFEwHQYDVR0OBBYEFGYM6HhP8yZ17eXw5nOfQ971u1l9MB8GA1UdIwQY
MBaAFGYM6HhP8yZ17eXw5nOfQ971u1l9MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAFmFkUodKTXeT683GEj4SoiMbDL8d3x+Vc+kvLPC2Jloru4R
Qo0USu3eJZjNxKjmPbLii8gzf5ZmZHdytWQ+5irYjXBHrE9tPgmpavhM+0otpnUd
vYosnfwv/aQEIiqeMkpqzbSKvb2I+TVpAC1xb6qbYE95tnsX/KEdAoJ/SAcZLGYQ
LKGTjz3eKlgUWy69uwzHXkie8hxDVRlyA7cFY4AAqsLhL2KQPWtMT7fRKrVKfLYd
Qq7tJAMLnPnAdAUousI0RDcLpB8adGkhZH66lL4oV9U+aQ0dA0oiqSKZtMoHeWbr
/L0ti7ZOfxOxRRCzt8KdLo/kGNTfAz+74P0MY80=
-----END CERTIFICATE-----
'''
"#,
            concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/data/ca.pem"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/data/ca.pem")
        );

        let with_ca = read_local_server_config(&ca_backend).expect("can parse backends with ca");
        let dog_backend = with_ca.backends.0.get("dog").expect("fetch failed :(");
        assert!(dog_backend.ca_certs.is_empty());
        let shark_backend = with_ca
            .backends
            .0
            .get("shark.server")
            .expect("no blåhaj :(");
        assert_eq!(3, shark_backend.ca_certs.len());
    }
}
