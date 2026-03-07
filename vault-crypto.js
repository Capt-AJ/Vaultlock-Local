const VaultCrypto = (() => {
  const KDF_ROUNDS = 600000;
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
    const buffer = encoder.encode(password);
    try {
      return await crypto.subtle.importKey(
        "raw",
        buffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
    } finally {
      buffer.fill(0);
    }
  }

  async function deriveVaultKey(masterPassword, saltBase64, iterations = KDF_ROUNDS) {
    if (!masterPassword || typeof masterPassword !== "string") {
      throw new Error("Master password is required.");
    }
    if (!saltBase64 || typeof saltBase64 !== "string") {
      throw new Error("Vault salt is missing.");
    }

    const material = await importPassword(masterPassword);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations,
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

  function buildAadBytes(aadText) {
    if (!aadText) {
      return null;
    }
    return encoder.encode(aadText);
  }

  async function sealTextWithKey(plainText, key, aadText = "") {
    const iv = randomBytes(IV_BYTES);
    const aadBytes = buildAadBytes(aadText);

    const cipherBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: aadBytes || undefined,
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

  async function openTextWithKey(cipherBase64, key, aadText = "") {
    try {
      const packed = fromBase64(cipherBase64);

      if (packed.byteLength <= IV_BYTES) {
        throw new Error("Malformed payload");
      }

      const iv = packed.slice(0, IV_BYTES);
      const cipherBytes = packed.slice(IV_BYTES);
      const aadBytes = buildAadBytes(aadText);
      const plainBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aadBytes || undefined,
        },
        key,
        cipherBytes
      );

      return decoder.decode(plainBuffer);
    } catch (_error) {
      throw new Error("Decryption failed.");
    }
  }

  async function sealText(plainText, masterPassword, saltBase64, iterations = KDF_ROUNDS, aadText = "") {
    const key = await deriveVaultKey(masterPassword, saltBase64, iterations);
    return sealTextWithKey(plainText, key, aadText);
  }

  async function openText(cipherBase64, masterPassword, saltBase64, iterations = KDF_ROUNDS, aadText = "") {
    const key = await deriveVaultKey(masterPassword, saltBase64, iterations);
    return openTextWithKey(cipherBase64, key, aadText);
  }

  return {
    KDF_ROUNDS,
    SALT_BYTES,
    IV_BYTES,
    KEY_BITS,
    deriveVaultKey,
    sealText,
    openText,
    sealTextWithKey,
    openTextWithKey,
    toBase64,
    fromBase64,
    randomBytes,
  };
})();
