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

  async function writeVault(entries, masterPassword) {
    const salt = await ensureSalt();
    const encrypted = await VaultCrypto.sealText(JSON.stringify(entries), masterPassword, salt);
    await localSet({ [ENCRYPTED_VAULT_KEY]: encrypted });
  }

  async function readVault(masterPassword) {
    const salt = await ensureSalt();
    const result = await localGet([ENCRYPTED_VAULT_KEY]);
    const encrypted = result[ENCRYPTED_VAULT_KEY];

    if (!encrypted) {
      return [];
    }

    try {
      const plainText = await VaultCrypto.openText(encrypted, masterPassword, salt);
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
    writeVault,
    readVault,
  };
})();
