const VaultCrypto = (() => {
  const KDF_ROUNDS = 310000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const KEY_BITS = 256;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function toBase64(uint8) {
    let text = "";
    const slice = 0x8000;

    for (let offset = 0; offset < uint8.length; offset += slice) {
      text += String.fromCharCode(...uint8.subarray(offset, offset + slice));
    }

    return btoa(text);
  }

  function fromBase64(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }

  function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  async function importPassword(password) {
    // encode password to a temporary buffer so we can erase it after use.
    const buffer = encoder.encode(password);
    try {
      return crypto.subtle.importKey(
        "raw",
        buffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
    } finally {
      // overwrite sensitive bytes
      buffer.fill(0);
    }
  }

  async function deriveVaultKey(masterPassword, saltBase64) {
    const material = await importPassword(masterPassword);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: KDF_ROUNDS,
        salt: fromBase64(saltBase64),
      },
      material,
      {
        name: "AES-GCM",
        length: KEY_BITS,
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // derive a key suitable for encrypting/decrypting vault data. callers can cache the
  // resulting CryptoKey and wipe the password string from memory immediately after.
  async function deriveVaultKey(masterPassword, saltBase64) {
    const material = await importPassword(masterPassword);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: KDF_ROUNDS,
        salt: fromBase64(saltBase64),
      },
      material,
      {
        name: "AES-GCM",
        length: KEY_BITS,
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // new helper that encrypts plaintext using an already-derived CryptoKey. this keeps the
  // vault repository logic separate from password handling and allows the UI to forget the
  // master password after the key is created.
  async function sealTextWithKey(plainText, key) {
    const iv = randomBytes(IV_BYTES);
    const cipherBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      key,
      encoder.encode(plainText)
    );

    const cipherBytes = new Uint8Array(cipherBuffer);
    const packed = new Uint8Array(iv.length + cipherBytes.length);
    packed.set(iv, 0);
    packed.set(cipherBytes, iv.length);
    return toBase64(packed);
  }

  // decrypt a base64 payload using a pre‑derived CryptoKey.
  async function openTextWithKey(cipherBase64, key) {
    try {
      const packed = fromBase64(cipherBase64);

      if (packed.byteLength <= IV_BYTES) {
        throw new Error("Malformed payload");
      }

      const iv = packed.slice(0, IV_BYTES);
      const cipherBytes = packed.slice(IV_BYTES);
      const plainBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        },
        key,
        cipherBytes
      );

      return decoder.decode(plainBuffer);
    } catch (_error) {
      throw new Error("Incorrect master password or corrupted vault");
    }
  }

  return {
    KDF_ROUNDS,
    SALT_BYTES,
    deriveVaultKey,

    // password-based helpers (legacy wrappers kept for compatibility)
    sealText,
    openText,

    // key‑based helpers – preferred for lower exposure of the master password.
    sealTextWithKey,
    openTextWithKey,

    toBase64,
    fromBase64,
    randomBytes,
  };
})();
