// contracts/identity-registry/src/did_resolver.rs

use soroban_sdk::{contracttype, Address, Bytes, Env, Map, String, Symbol, Vec};

/// Supported DID methods.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidMethod {
    Soroban,
    Web,
    Key,
    Custom(Symbol),
}

/// A verification method entry in a DID document.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub controller: String,
    pub public_key: Bytes,
}

/// A service entry in a DID document.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}

/// A resolved DID document.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidDocument {
    pub id: String,
    pub controller: String,
    pub verification_methods: Vec<VerificationMethod>,
    pub services: Vec<Service>,
}

/// Errors produced by the DID resolver.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidResolverError {
    UnsupportedDidMethod,
    MalformedDid,
    DidMethodAlreadyRegistered,
}

/// Storage keys for the DID resolver.
#[contracttype]
pub enum DidResolverKey {
    /// Registered custom DID methods -> handler identifier.
    MethodRegistry(Symbol),
    /// Cached resolved documents keyed by DID string.
    ResolutionCache(String),
    /// Admin authorized to register methods.
    Admin,
}

/// The universal DID resolver.
pub struct DidResolver;

impl DidResolver {
    /// Initialize the resolver with an admin.
    pub fn initialize(env: &Env, admin: Address) {
        env.storage()
            .persistent()
            .set(&DidResolverKey::Admin, &admin);
    }

    fn admin(env: &Env) -> Address {
        env.storage()
            .persistent()
            .get(&DidResolverKey::Admin)
            .expect("not initialized")
    }

    /// Register a custom DID method. Admin-gated.
    pub fn register_did_method(
        env: &Env,
        caller: Address,
        method: Symbol,
        handler: Symbol,
    ) -> Result<(), DidResolverError> {
        caller.require_auth();
        let admin = Self::admin(env);
        if caller != admin {
            return Err(DidResolverError::UnsupportedDidMethod);
        }

        let key = DidResolverKey::MethodRegistry(method.clone());
        if env.storage().persistent().has(&key) {
            return Err(DidResolverError::DidMethodAlreadyRegistered);
        }

        env.storage().persistent().set(&key, &handler);
        Ok(())
    }

    /// Check whether a custom method is registered.
    pub fn is_method_registered(env: &Env, method: Symbol) -> bool {
        env.storage()
            .persistent()
            .has(&DidResolverKey::MethodRegistry(method))
    }

    /// Parse the method prefix from a DID string of the form `did:<method>:<id>`.
    fn parse_method(did: &String) -> Result<(Symbol, String), DidResolverError> {
        let bytes = did.to_bytes();
        let len = bytes.len();

        // Must start with "did:"
        if len < 5 {
            return Err(DidResolverError::MalformedDid);
        }
        let prefix = [b'd', b'i', b'd', b':'];
        for (i, b) in prefix.iter().enumerate() {
            if bytes.get(i as u32) != Some(*b) {
                return Err(DidResolverError::MalformedDid);
            }
        }

        // Find the second colon separating method from id.
        let mut method_end: Option<u32> = None;
        let mut i: u32 = 4;
        while i < len {
            if bytes.get(i) == Some(b':') {
                method_end = Some(i);
                break;
            }
            i += 1;
        }

        let method_end = method_end.ok_or(DidResolverError::MalformedDid)?;
        if method_end == 4 {
            // empty method
            return Err(DidResolverError::MalformedDid);
        }
        if method_end + 1 >= len {
            // empty id
            return Err(DidResolverError::MalformedDid);
        }

        let method_bytes = bytes.slice(4..method_end);
        let id_bytes = bytes.slice(method_end + 1..len);

        let method_str = String::from_bytes(env, &method_bytes);
        let id_str = String::from_bytes(env, &id_bytes);

        // Convert method string to Symbol.
        let method_sym = Symbol::new(env, &method_str.to_string());

        Ok((method_sym, id_str))
    }

    /// Resolve a DID string into a DID document.
    pub fn resolve_did(env: &Env, did: String) -> Result<DidDocument, DidResolverError> {
        // Check cache first.
        let cache_key = DidResolverKey::ResolutionCache(did.clone());
        if let Some(cached) = env
            .storage()
            .persistent()
            .get::<DidResolverKey, DidDocument>(&cache_key)
        {
            return Ok(cached);
        }

        let (method, id) = Self::parse_method(&did)?;

        let method_str = method.to_string();
        let doc = if method_str == String::from_slice(env, "soroban") {
            Self::resolve_soroban(env, &did, &id)?
        } else if method_str == String::from_slice(env, "web") {
            Self::resolve_web(env, &did, &id)?
        } else if method_str == String::from_slice(env, "key") {
            Self::resolve_key(env, &did, &id)?
        } else {
            // Custom method: must be registered.
            if !Self::is_method_registered(env, method.clone()) {
                return Err(DidResolverError::UnsupportedDidMethod);
            }
            Self::resolve_custom(env, &did, &id, method)?
        };

        // Store in cache.
        env.storage().persistent().set(&cache_key, &doc);
        Ok(doc)
    }

    /// Native registry lookup for `did:soroban:<address>`.
    fn resolve_soroban(
        env: &Env,
        did: &String,
        id: &String,
    ) -> Result<DidDocument, DidResolverError> {
        // The id is expected to be a Stellar address string.
        let address_str = id.to_string();
        let address = Address::from_string(&String::from_slice(env, &address_str));

        let mut vms: Vec<VerificationMethod> = Vec::new(env);
        vms.push_back(VerificationMethod {
            id: String::from_slice(env, &format!("{}#controller", did.to_string())),
            method_type: String::from_slice(env, "Ed25519VerificationKey2020"),
            controller: did.clone(),
            public_key: Bytes::new(env),
        });

        Ok(DidDocument {
            id: did.clone(),
            controller: address.to_string(),
            verification_methods: vms,
            services: Vec::new(env),
        })
    }

    /// URL mapping for `did:web:<domain>`.
    fn resolve_web(
        env: &Env,
        did: &String,
        id: &String,
    ) -> Result<DidDocument, DidResolverError> {
        let domain = id.to_string();
        if domain.is_empty() {
            return Err(DidResolverError::MalformedDid);
        }

        // Map to https URL: https://<domain>/.well-known/did.json
        let url = format!("https://{}/.well-known/did.json", domain);

        let mut services: Vec<Service> = Vec::new(env);
        services.push_back(Service {
            id: String::from_slice(env, &format!("{}#resolver", did.to_string())),
            service_type: String::from_slice(env, "DIDWebResolver"),
            endpoint: String::from_slice(env, &url),
        });

        Ok(DidDocument {
            id: did.clone(),
            controller: did.clone(),
            verification_methods: Vec::new(env),
            services,
        })
    }

    /// Base58 decoding for `did:key:<multibase>`.
    fn resolve_key(
        env: &Env,
        did: &String,
        id: &String,
    ) -> Result<DidDocument, DidResolverError> {
        let encoded = id.to_string();
        if encoded.is_empty() {
            return Err(DidResolverError::MalformedDid);
        }

        // Strip multibase prefix 'z' for base58btc.
        let payload = if encoded.starts_with('z') {
            &encoded[1..]
        } else {
            &encoded[..]
        };

        let decoded = Self::base58_decode(env, payload)
            .ok_or(DidResolverError::MalformedDid)?;

        let mut vms: Vec<VerificationMethod> = Vec::new(env);
        vms.push_back(VerificationMethod {
            id: String::from_slice(env, &format!("{}#keys-1", did.to_string())),
            method_type: String::from_slice(env, "Ed25519VerificationKey2020"),
            controller: did.clone(),
            public_key: decoded,
        });

        Ok(DidDocument {
            id: did.clone(),
            controller: did.clone(),
            verification_methods: vms,
            services: Vec::new(env),
        })
    }

    /// Dispatch to a registered custom method handler.
    fn resolve_custom(
        env: &Env,
        did: &String,
        id: &String,
        method: Symbol,
    ) -> Result<DidDocument, DidResolverError> {
        let handler: Symbol = env
            .storage()
            .persistent()
            .get(&DidResolverKey::MethodRegistry(method))
            .ok_or(DidResolverError::UnsupportedDidMethod)?;

        // Custom handlers produce a minimal document referencing the handler.
        let mut services: Vec<Service> = Vec::new(env);
        services.push_back(Service {
            id: String::from_slice(env, &format!("{}#handler", did.to_string())),
            service_type: String::from_slice(env, &handler.to_string()),
            endpoint: id.clone(),
        });

        Ok(DidDocument {
            id: did.clone(),
            controller: did.clone(),
            verification_methods: Vec::new(env),
            services,
        })
    }

    /// Decode a base58btc string into bytes.
    fn base58_decode(env: &Env, input: &str) -> Option<Bytes> {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        let mut result: Vec<u8> = Vec::new();
        let bytes = input.as_bytes();

        // Count leading '1's (zero bytes).
        let mut leading_zeros = 0usize;
        for &b in bytes {
            if b == b'1' {
                leading_zeros += 1;
            } else {
                break;
            }
        }

        // Big-number base conversion.
        let mut num: Vec<u8> = Vec::new();
        for &c in bytes {
            let mut carry = ALPHABET.iter().position(|&x| x == c)? as u32;
            for byte in num.iter_mut().rev() {
                let val = (*byte as u32) * 58 + carry;
                *byte = (val & 0xff) as u8;
                carry = val >> 8;
            }
            while carry > 0 {
                num.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }

        // Prepend leading zeros.
        for _ in 0..leading_zeros {
            result.push(0u8);
        }
        result.extend_from_slice(&num);

        Some(Bytes::from_slice(env, &result))
    }

    /// Clear a cached resolution.
    pub fn clear_cache(env: &Env, did: String) {
        env.storage()
            .persistent()
            .remove(&DidResolverKey::ResolutionCache(did));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        DidResolver::initialize(&env, admin.clone());
        (env, admin)
    }

    #[test]
    fn test_resolve_soroban() {
        let (env, _admin) = setup();
        let addr = Address::generate(&env);
        let did = String::from_slice(&env, &format!("did:soroban:{}", addr.to_string()));
        let doc = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_methods.len(), 1);
    }

    #[test]
    fn test_resolve_web() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "did:web:example.com");
        let doc = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.services.len(), 1);
        let endpoint = doc.services.get(0).unwrap().endpoint.to_string();
        assert!(endpoint.contains("example.com"));
    }

    #[test]
    fn test_resolve_key() {
        let (env, _admin) = setup();
        // "z6Mk..." style; use a valid base58 payload.
        let did = String::from_slice(&env, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let doc = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.get(0).unwrap().public_key.len() > 0);
    }

    #[test]
    fn test_resolve_custom_registered() {
        let (env, admin) = setup();
        let method = Symbol::new(&env, "example");
        let handler = Symbol::new(&env, "example_handler");
        DidResolver::register_did_method(&env, admin, method, handler).unwrap();

        let did = String::from_slice(&env, "did:example:12345");
        let doc = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc.id, did);
    }

    #[test]
    fn test_unsupported_method() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "did:unknown:12345");
        let res = DidResolver::resolve_did(&env, did);
        assert_eq!(res, Err(DidResolverError::UnsupportedDidMethod));
    }

    #[test]
    fn test_malformed_no_prefix() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "notadid");
        let res = DidResolver::resolve_did(&env, did);
        assert_eq!(res, Err(DidResolverError::MalformedDid));
    }

    #[test]
    fn test_malformed_missing_id() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "did:web:");
        let res = DidResolver::resolve_did(&env, did);
        assert_eq!(res, Err(DidResolverError::MalformedDid));
    }

    #[test]
    fn test_malformed_missing_method() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "did::12345");
        let res = DidResolver::resolve_did(&env, did);
        assert_eq!(res, Err(DidResolverError::MalformedDid));
    }

    #[test]
    fn test_duplicate_method_registration() {
        let (env, admin) = setup();
        let method = Symbol::new(&env, "example");
        let handler = Symbol::new(&env, "example_handler");
        DidResolver::register_did_method(&env, admin.clone(), method.clone(), handler.clone())
            .unwrap();
        let res = DidResolver::register_did_method(&env, admin, method, handler);
        assert_eq!(res, Err(DidResolverError::DidMethodAlreadyRegistered));
    }

    #[test]
    fn test_cache() {
        let (env, _admin) = setup();
        let did = String::from_slice(&env, "did:web:example.com");
        let _ = DidResolver::resolve_did(&env, did.clone()).unwrap();
        // Second call should hit cache.
        let doc = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc.id, did);
        DidResolver::clear_cache(&env, did.clone());
        let doc2 = DidResolver::resolve_did(&env, did.clone()).unwrap();
        assert_eq!(doc2.id, did);
    }
}