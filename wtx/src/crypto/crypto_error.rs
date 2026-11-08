/// Crypto error
#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
  /// Diffie Hellman Error
  DiffieHellmanError,
  /// Ephemeral Secret Key Error
  EphemeralSecretKeyError,
  /// Opaque error originated from `Hkdf::expand`
  HkdfExpandError,
  /// Opaque error originated from `Hkdf::from_prk`
  HkdfFromPrkError,
  /// A tag does not match the computed value
  HmacVerificationError,
  /// Opaque error originated from AES operations
  InvalidAesData,
  /// Opaque error originated from AES-128 operations
  InvalidAes128GcmData,
  /// Opaque error originated from AES-256 operations
  InvalidAes256GcmData,
  /// Opaque error originated from `Chacha20Poly1305` operations
  InvalidChacha20Poly1305Data,
  /// Invalid Hash Length
  InvalidHashLength,
  /// Opaque error originated from header protection operations, for example, a key with the
  /// wrong length
  InvalidHeaderProtection,
  /// Large HKDF Output
  LargeHkdfOutput,
  /// Public Key Agreement Error
  PublicKeyAgreementError,
  /// Signature Error
  SignatureError,
  /// Sig Key Error
  SigningKeyError,
  /// The selected crypto backend does not implement header protection
  UnsupportedHeaderProtection,
  /// Unsupported Signature Oid
  UnsupportedKeyOid,
  /// Unsupported Signature Oid
  UnsupportedSignatureOid,
  /// Unknown Signature Type
  UnknownSignatureTy,
}
