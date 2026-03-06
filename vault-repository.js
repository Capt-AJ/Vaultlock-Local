const VaultRepository = (() => {
  const ENCRYPTED_VAULT_KEY = "vault_encrypted";
  const SALT_STORAGE_KEY = "vault_salt";

  function localGet(keys) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.get(keys, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        resolve(result);
      });
    });
  }

  function localSet(value) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.set(value, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        resolve();
      });
    });
  }

  async function ensureSalt() {
    const result = await localGet([SALT_STORAGE_KEY]);
    const existingSalt = result[SALT_STORAGE_KEY];

    if (typeof existingSalt === "string" && existingSalt.length > 0) {
      return existingSalt;
    }

    const createdSalt = VaultCrypto.toBase64(VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES));
    await localSet({ [SALT_STORAGE_KEY]: createdSalt });
    return createdSalt;
  }

  async function vaultExists() {
    const result = await localGet([ENCRYPTED_VAULT_KEY]);
    return typeof result[ENCRYPTED_VAULT_KEY] === "string" && result[ENCRYPTED_VAULT_KEY].length > 0;
  }

  // convert a master password string into a CryptoKey that can be reused for
  // multiple encrypt/decrypt operations. callers should clear their copy of the
  // password immediately after deriving the key.
  async function deriveKey(masterPassword) {
    const salt = await ensureSalt();
    return VaultCrypto.deriveVaultKey(masterPassword, salt);
  }

  // write vault data using an already-derived CryptoKey.
  async function writeVault(entries, key) {
    const salt = await ensureSalt(); // ensure salt exists, but key derivation already used it
    const encrypted = await VaultCrypto.sealTextWithKey(JSON.stringify(entries), key);
    await localSet({ [ENCRYPTED_VAULT_KEY]: encrypted });
  }

  // read vault data using a CryptoKey, returning null when decryption fails.
  async function readVault(key) {
    // salt need not be re-fetched here; this call keeps the same contract as before
    await ensureSalt();
    const result = await localGet([ENCRYPTED_VAULT_KEY]);
    const encrypted = result[ENCRYPTED_VAULT_KEY];

    if (!encrypted) {
      return [];
    }

    try {
      const plainText = await VaultCrypto.openTextWithKey(encrypted, key);
      const parsed = JSON.parse(plainText);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_error) {
      return null;
    }
  }

  return {
    ENCRYPTED_VAULT_KEY,
    SALT_STORAGE_KEY,
    ensureSalt,
    vaultExists,
    deriveKey,
    writeVault,
    readVault,
  };
})();
