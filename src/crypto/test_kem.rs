use ml_kem::{MlKem768, MlKem1024, KemCore, EncodedSizeUser};
use ml_kem::kem::{Decapsulate, Encapsulate};
use rand::rngs::OsRng;

pub fn test_pqc() {
    let mut rng = OsRng;
    let (decaps_key, encaps_key) = MlKem768::generate(&mut rng);
    let (ciphertext, shared_secret) = encaps_key.encapsulate(&mut rng).unwrap();
    let recovered_secret = decaps_key.decapsulate(&ciphertext).unwrap();
    assert_eq!(shared_secret.as_slice(), recovered_secret.as_slice());
}
