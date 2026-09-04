use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, MlKem768, MlKem768Params,
};
use rand::{CryptoRng, RngCore};

use crate::crypto::{CryptoError, PqcSuite};

pub struct PqcEncapsulationResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub decapsulation_key_bytes: Vec<u8>,
}

/// Generates a keypair and encapsulates a shared secret for the specified PQC suite.
pub fn pqc_encapsulate<R: RngCore + CryptoRng>(
    suite: PqcSuite,
    rng: &mut R,
) -> Result<PqcEncapsulationResult, CryptoError> {
    match suite {
        PqcSuite::MlKem768 => {
            let (decaps_key, encaps_key) = MlKem768::generate(rng);
            let (ciphertext, shared_secret) = encaps_key
                .encapsulate(rng)
                .map_err(|e| CryptoError::KemError(format!("ML-KEM-768 encapsulation failed: {:?}", e)))?;

            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared_secret.as_slice());

            let decaps_bytes = decaps_key.as_bytes().as_slice().to_vec();
            let ct_bytes = ciphertext.as_slice().to_vec();

            Ok(PqcEncapsulationResult {
                ciphertext: ct_bytes,
                shared_secret: ss,
                decapsulation_key_bytes: decaps_bytes,
            })
        }
        PqcSuite::MlKem1024 => {
            let (decaps_key, encaps_key) = MlKem1024::generate(rng);
            let (ciphertext, shared_secret) = encaps_key
                .encapsulate(rng)
                .map_err(|e| CryptoError::KemError(format!("ML-KEM-1024 encapsulation failed: {:?}", e)))?;

            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared_secret.as_slice());

            let decaps_bytes = decaps_key.as_bytes().as_slice().to_vec();
            let ct_bytes = ciphertext.as_slice().to_vec();

            Ok(PqcEncapsulationResult {
                ciphertext: ct_bytes,
                shared_secret: ss,
                decapsulation_key_bytes: decaps_bytes,
            })
        }
    }
}

/// Decapsulates the PQC ciphertext using the decrypted decapsulation key bytes.
pub fn pqc_decapsulate(
    suite: PqcSuite,
    decaps_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    match suite {
        PqcSuite::MlKem768 => {
            let dk_array: &Encoded<DecapsulationKey<MlKem768Params>> = decaps_key_bytes
                .try_into()
                .map_err(|_| CryptoError::KemError("Invalid ML-KEM-768 decapsulation key length".into()))?;
            let decaps_key = DecapsulationKey::<MlKem768Params>::from_bytes(dk_array);

            let ct_array: &Ciphertext<MlKem768> = ciphertext_bytes
                .try_into()
                .map_err(|_| CryptoError::KemError("Invalid ML-KEM-768 ciphertext length".into()))?;

            let shared_secret = decaps_key
                .decapsulate(ct_array)
                .map_err(|e| CryptoError::KemError(format!("ML-KEM-768 decapsulation failed: {:?}", e)))?;

            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared_secret.as_slice());
            Ok(ss)
        }
        PqcSuite::MlKem1024 => {
            let dk_array: &Encoded<DecapsulationKey<MlKem1024Params>> = decaps_key_bytes
                .try_into()
                .map_err(|_| CryptoError::KemError("Invalid ML-KEM-1024 decapsulation key length".into()))?;
            let decaps_key = DecapsulationKey::<MlKem1024Params>::from_bytes(dk_array);

            let ct_array: &Ciphertext<MlKem1024> = ciphertext_bytes
                .try_into()
                .map_err(|_| CryptoError::KemError("Invalid ML-KEM-1024 ciphertext length".into()))?;

            let shared_secret = decaps_key
                .decapsulate(ct_array)
                .map_err(|e| CryptoError::KemError(format!("ML-KEM-1024 decapsulation failed: {:?}", e)))?;

            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared_secret.as_slice());
            Ok(ss)
        }
    }
}
