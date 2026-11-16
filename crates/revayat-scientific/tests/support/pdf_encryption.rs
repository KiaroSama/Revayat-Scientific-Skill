//! Native AES256 fixture, including a valid empty-user-password variant.
use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
use lopdf::{Document, EncryptionState, EncryptionVersion, Permissions};
pub fn encrypt(document: &mut Document, user_password: &str) {
    let filter: std::sync::Arc<dyn CryptFilter> = std::sync::Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: std::collections::BTreeMap::from([(b"StdCF".to_vec(), filter)]),
        file_encryption_key: &[7; 32],
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: "synthetic-owner",
        user_password,
        permissions: Permissions::all(),
    })
    .unwrap();
    document.encrypt(&state).unwrap();
}
