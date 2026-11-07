use crate::{
  collections::{ShortBoxSliceU8, ShortBoxSliceU16, VectorUsize},
  crypto::{DynSigningKey, DynSigningOutput},
  rng::CryptoRng,
  tls::{
    SignatureScheme, TlsCtx, TlsCtxSk, TlsCtxSkLoader, TlsError, TlsMode,
    tls_ctx::{secret_key_from_pem, secret_key_ty},
  },
  x509::{KeyTy, SignatureTy},
};
use alloc::vec::Vec;
use core::hint::cold_path;

/// Secret Key Context
///
/// Secure connection with unprotected private key. Data is encrypted and certificates are verified.
///
/// Used by servers. Each key is parsed once, when loaded, for every signature its type can make:
/// a handshake signs with the parsed key instead of parsing it again, which with RSA cost a dozen
/// allocations and the key's checks every time.
#[derive(Debug, Default)]
pub struct SkCtx {
  keys: ShortBoxSliceU8<(ShortBoxSliceU16<u8>, KeyTy)>,
  /// By key, then by [`SignatureTy`]: the parsed key, if the backend could parse it so.
  parsed: Vec<[Option<DynSigningKey>; SignatureTy::len()]>,
}

impl SkCtx {
  fn new(keys: ShortBoxSliceU8<(ShortBoxSliceU16<u8>, KeyTy)>) -> Self {
    let parsed = keys
      .iter()
      .map(|(der, key_ty)| {
        let mut by_ty: [Option<DynSigningKey>; SignatureTy::len()] = Default::default();
        for sc in SignatureScheme::PRIORITY {
          let st = sc.handshake_st();
          if sc.cert_kt() == *key_ty
            && let Some(slot @ None) = by_ty.get_mut(st as usize)
          {
            // A key that doesn't parse is parsed again when it signs, which reports why.
            *slot = st.sign_key_from_pkcs8(der).ok();
          }
        }
        by_ty
      })
      .collect();
    Self { keys, parsed }
  }
}

impl TlsCtx for SkCtx {
  const TY: TlsMode = TlsMode::Verified;
}

impl TlsCtxSk for SkCtx {
  type Signature = DynSigningOutput;

  #[inline]
  fn sign<RNG>(
    &self,
    msg: &[u8],
    rng: &mut RNG,
    sc: SignatureScheme,
  ) -> crate::Result<Self::Signature>
  where
    RNG: CryptoRng,
  {
    let kt = sc.cert_kt();
    let st = sc.handshake_st();
    for (idx, value) in self.keys.iter().enumerate() {
      if value.1 == kt {
        if let Some(key) = self.parsed.get(idx).and_then(|el| el.get(st as usize)?.as_ref()) {
          return key.sign(msg, rng);
        }
        return st.sign_key_from_pkcs8(&value.0)?.sign(msg, rng);
      }
    }
    cold_path();
    Err(TlsError::UnsupportedSignAlgorithm.into())
  }
}

impl TlsCtxSkLoader for SkCtx {
  type SkInputDer<'data> = ShortBoxSliceU16<u8>;
  type SkInputPem<'data> = &'data [u8];

  #[inline]
  fn from_ders<'data>(
    input: impl IntoIterator<Item = Self::SkInputDer<'data>>,
  ) -> crate::Result<Self> {
    let mut vector = VectorUsize::new();
    for value in input {
      let key_ty = secret_key_ty(&value)?;
      vector.push((value, key_ty))?;
    }
    Ok(Self::new(vector.try_into()?))
  }

  /// From a secret key in PEM format.
  #[inline]
  fn from_pems<'data>(
    input: impl IntoIterator<Item = Self::SkInputPem<'data>>,
  ) -> crate::Result<Self> {
    let mut vector = VectorUsize::new();
    for pem in input {
      vector.push(secret_key_from_pem(pem)?)?;
    }
    Ok(Self::new(vector.try_into()?))
  }
}
