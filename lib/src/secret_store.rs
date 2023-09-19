use {bytes::Bytes, std::collections::HashMap};

#[derive(Clone, Debug, Default)]
pub struct SecretStores {
    stores: HashMap<String, SecretStore>,
}

impl SecretStores {
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
        }
    }

    pub fn get_store(&self, name: &str) -> Option<&SecretStore> {
        self.stores.get(name)
    }

    pub fn add_store(&mut self, name: String, store: SecretStore) {
        self.stores.insert(name, store);
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecretStore {
    secrets: HashMap<String, Secret>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    pub fn get_secret(&self, name: &str) -> Option<&Secret> {
        self.secrets.get(name)
    }

    pub fn add_secret(&mut self, name: String, secret: Bytes) {
        self.secrets.insert(name, Secret { plaintext: secret });
    }
}

#[derive(Clone, Debug, Default)]
pub struct Secret {
    plaintext: Bytes,
}

impl Secret {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

#[derive(Clone, Debug)]
pub enum SecretLookup {
    Standard {
        store_name: String,
        secret_name: String,
    },
    Injected {
        plaintext: Vec<u8>,
    },
}
