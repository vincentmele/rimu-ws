#[cfg(any(feature = "crypto-alr", feature = "crypto-ring"))]
macro_rules! common_aead_functions {
  () => {
    #[inline]
    fn local_decrypt<'data, const S: usize>(
      algorithm: &'static Algorithm,
      associated_data: &[u8],
      data: &'data mut [u8],
      error: CryptoError,
      nonce: [u8; AEAD_NONCE_LEN],
      secret: &[u8; S],
    ) -> crate::Result<&'data mut [u8]> {
      let bytes = LessSafeKey::new(UnboundKey::new(algorithm, secret).map_err(|_err| error)?)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(associated_data), data)
        .map_err(|_err| error)?;
      Ok(bytes)
    }

    #[inline]
    fn local_encrypt_vectored_data<const S: usize>(
      algorithm: &'static Algorithm,
      associated_data: &[u8],
      error: CryptoError,
      nonce: [u8; AEAD_NONCE_LEN],
      plaintext: &mut [u8],
      secret: &[u8; S],
    ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
      let tag = LessSafeKey::new(UnboundKey::new(algorithm, secret).map_err(|_err| error)?)
        .seal_in_place_separate_tag(
          Nonce::assume_unique_for_key(nonce),
          Aad::from(associated_data),
          plaintext,
        )
        .map_err(|_err| error)?
        .as_ref()
        .try_into()?;
      Ok(tag)
    }
  };
}

#[cfg(any(feature = "crypto-alr", feature = "crypto-ring"))]
macro_rules! common_aead_key_functions {
  () => {
    #[inline]
    fn local_new_key(
      algorithm: &'static Algorithm,
      error: CryptoError,
      key: &[u8],
    ) -> crate::Result<LessSafeKey> {
      match UnboundKey::new(algorithm, key) {
        Ok(elem) => Ok(LessSafeKey::new(elem)),
        Err(_err) => {
          core::hint::cold_path();
          Err(error.into())
        }
      }
    }

    #[inline]
    fn local_open_key<'data>(
      aad: &[u8],
      data: &'data mut [u8],
      error: CryptoError,
      key: &LessSafeKey,
      nonce: [u8; AEAD_NONCE_LEN],
    ) -> crate::Result<&'data mut [u8]> {
      key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(error)
      })
    }

    #[inline]
    fn local_seal_key(
      aad: &[u8],
      data: &mut [u8],
      error: CryptoError,
      key: &LessSafeKey,
      nonce: [u8; AEAD_NONCE_LEN],
    ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
      let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
        .map_err(|_err| {
          core::hint::cold_path();
          crate::Error::from(error)
        })?;
      Ok(tag.as_ref().try_into()?)
    }
  };
}

#[cfg(any(feature = "crypto-alr", feature = "crypto-ring"))]
macro_rules! common_hp_key_functions {
  () => {
    #[inline]
    fn local_new_hp(
      algorithm: &'static Algorithm,
      key: &[u8],
    ) -> crate::Result<HeaderProtectionKey> {
      HeaderProtectionKey::new(algorithm, key).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(CryptoError::InvalidHeaderProtection)
      })
    }

    #[inline]
    fn local_mask_hp(key: &HeaderProtectionKey, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
      key.new_mask(sample).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(CryptoError::InvalidHeaderProtection)
      })
    }
  };
}

#[cfg(any(feature = "crypto-alr", feature = "crypto-ring"))]
macro_rules! common_hkdf_functions {
  ($krate:ident) => {
    #[inline]
    fn local_extract<const N: usize>(
      algorithm_hkdf: hkdf::Algorithm,
      algorithm_hmac: hmac::Algorithm,
      salt: Option<&[u8]>,
      ikm: &[u8],
    ) -> ([u8; N], Prk) {
      let salt_bytes = match salt {
        Some(el) => el,
        None => &[0u8; N],
      };
      let key = Key::new(algorithm_hmac, salt_bytes);
      let tag = hmac::sign(&key, ikm);
      let prk_bytes = tag.as_ref();
      let array = if let Ok(elem) = tag.as_ref().try_into() { elem } else { unlikely_elem([0; N]) };
      let prk = Prk::new_less_safe(algorithm_hkdf, prk_bytes);
      (array, prk)
    }

    #[inline]
    fn local_compute<'data, const N: usize>(
      algorithm: hmac::Algorithm,
      data: impl IntoIterator<Item = &'data [u8]>,
      key: &[u8],
    ) -> crate::Result<[u8; N]> {
      let key = Key::new(algorithm, key);
      let mut ctx = Context::with_key(&key);
      for chunk in data {
        ctx.update(chunk);
      }
      Ok(ctx.sign().as_ref().try_into()?)
    }

    #[inline]
    fn local_expand(info: &[u8], okm: &mut [u8], value: &Prk) -> crate::Result<()> {
      struct OkmLen(usize);
      impl $krate::hkdf::KeyType for OkmLen {
        #[inline]
        fn len(&self) -> usize {
          self.0
        }
      }

      value
        .expand(&[info], OkmLen(okm.len()))
        .and_then(|elem| elem.fill(okm))
        .map_err(|_err| CryptoError::HkdfExpandError)?;
      Ok(())
    }
  };
}

macro_rules! _create_wrappers {
  ($(
    $(#[$meta:meta])*
    $name:ident<$($param:ident $(: $bound:path)?)?>($($ty:ty)?)
  ),* $(,)?) => {
    $(
      /// A wrapper used to generalize third-party dependencies.
      $(#[$meta])*
      #[allow(missing_copy_implementations, reason = "too many structures to control")]
      pub struct $name<$($param $(: $bound)?)?>($(pub(crate) $ty)?);

      impl<$($param $(: $bound)?)?> $name<$($param)?> {
        /// New instance
        #[inline]
        pub const fn new($(value: $ty)?) -> Self {
          Self(
            $({
              let _expander: Option<$ty> = None;
              value
            })?
          )
        }
      }

      impl<$($param $(: $bound)?)?> core::fmt::Debug for $name<$($param)?> {
        #[inline]
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          f.write_str(stringify!($name))
        }
      }
    )*
  };
}

// Wrappers of the keys that QUIC keeps in pooled connection slots: whatever was expanded from the
// key is dropped and then overwritten when the wrapper is dropped, so the next owner of the slot
// cannot read it.
macro_rules! _create_key_wrappers {
  ($(
    $(#[$meta:meta])*
    $name:ident($ty:ty)
  ),* $(,)?) => {
    $(
      /// A wrapper used to generalize third-party dependencies. The bytes of the key are
      /// overwritten with zeros when it is dropped.
      $(#[$meta])*
      pub struct $name(pub(crate) core::mem::ManuallyDrop<$ty>);

      impl $name {
        /// Takes ownership of an already expanded key.
        #[inline]
        pub(crate) fn from_key(value: $ty) -> Self {
          Self(core::mem::ManuallyDrop::new(value))
        }
      }

      impl Drop for $name {
        #[inline]
        fn drop(&mut self) {
          // SAFETY: the field is only dropped here, and `self` is not used after `drop`
          unsafe { crate::crypto::drop_and_zero(&mut self.0) };
        }
      }

      impl core::fmt::Debug for $name {
        #[inline]
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          f.write_str(stringify!($name))
        }
      }
    )*
  };
}
