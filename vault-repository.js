const VaultRepository = (() => {
  const LEGACY_ENCRYPTED_VAULT_KEY = "vault_encrypted";
  const LEGACY_SALT_STORAGE_KEY = "vault_salt";
  const VAULT_BUNDLE_KEY = "vault_bundle_v2";
  const VAULT_VERSION = 2;

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

  function localRemove(keys) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.remove(keys, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        resolve();
      });
    });
  }

  function isObject(value) {
    return typeof value === "object" && value !== null;
  }

  function buildHeader(kdf) {
    return {
      version: VAULT_VERSION,
      cipher: "AES-GCM",
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: Number(kdf.iterations),
        salt: String(kdf.salt),
      },
    };
  }

  function headerAad(header) {
    return JSON.stringify(header);
  }

  function createKdf(iterations = VaultCrypto.KDF_ROUNDS) {
    return {
      iterations,
      salt: VaultCrypto.toBase64(VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES)),
    };
  }

  async function deriveKeyFromKdf(masterPassword, kdf) {
    return VaultCrypto.deriveVaultKey(masterPassword, kdf.salt, kdf.iterations);
  }

  async function encryptEntries(entries, key, kdf) {
    const header = buildHeader(kdf);
    const payload = await VaultCrypto.sealTextWithKey(JSON.stringify(entries), key, headerAad(header));
    return {
      ...header,
      payload,
      updatedAt: new Date().toISOString(),
    };
  }

  function parseEntries(text) {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  }

  async function decryptBundle(bundle, key) {
    if (!isObject(bundle) || bundle.version !== VAULT_VERSION || !bundle.kdf || typeof bundle.payload !== "string") {
      throw new Error("Vault data is malformed.");
    }

    const header = {
      version: bundle.version,
      cipher: bundle.cipher,
      kdf: bundle.kdf,
    };

    const plainText = await VaultCrypto.openTextWithKey(bundle.payload, key, headerAad(header));
    return parseEntries(plainText);
  }

  async function getBundle() {
    const result = await localGet([VAULT_BUNDLE_KEY]);
    return isObject(result[VAULT_BUNDLE_KEY]) ? result[VAULT_BUNDLE_KEY] : null;
  }

  async function getLegacy() {
    const result = await localGet([LEGACY_ENCRYPTED_VAULT_KEY, LEGACY_SALT_STORAGE_KEY]);
    return {
      encrypted: typeof result[LEGACY_ENCRYPTED_VAULT_KEY] === "string" ? result[LEGACY_ENCRYPTED_VAULT_KEY] : "",
      salt: typeof result[LEGACY_SALT_STORAGE_KEY] === "string" ? result[LEGACY_SALT_STORAGE_KEY] : "",
    };
  }

  async function purgeLegacy() {
    await localRemove([LEGACY_ENCRYPTED_VAULT_KEY, LEGACY_SALT_STORAGE_KEY]);
  }

  async function vaultExists() {
    const bundle = await getBundle();
    if (bundle) {
      return true;
    }

    const legacy = await getLegacy();
    return legacy.encrypted.length > 0;
  }

  async function writeBundle(bundle) {
    await localSet({ [VAULT_BUNDLE_KEY]: bundle });
  }

  async function createVault(masterPassword, initialEntries = []) {
    const kdf = createKdf();
    const key = await deriveKeyFromKdf(masterPassword, kdf);
    const bundle = await encryptEntries(initialEntries, key, kdf);
    await writeBundle(bundle);
    await purgeLegacy();
    return key;
  }

  async function migrateLegacyVault(masterPassword, encrypted, salt) {
    const oldKey = await VaultCrypto.deriveVaultKey(masterPassword, salt, VaultCrypto.KDF_ROUNDS);
    const plainText = await VaultCrypto.openTextWithKey(encrypted, oldKey);
    const entries = parseEntries(plainText);

    const newKdf = createKdf();
    const newKey = await deriveKeyFromKdf(masterPassword, newKdf);
    const bundle = await encryptEntries(entries, newKey, newKdf);
    await writeBundle(bundle);
    await purgeLegacy();

    return {
      entries,
      key: newKey,
    };
  }

  async function unlockVault(masterPassword) {
    const bundle = await getBundle();

    if (bundle) {
      const activeKdf = {
        iterations: Number(bundle.kdf?.iterations || VaultCrypto.KDF_ROUNDS),
        salt: String(bundle.kdf?.salt || ""),
      };
      const oldKey = await deriveKeyFromKdf(masterPassword, activeKdf);
      const entries = await decryptBundle(bundle, oldKey);

      // Rotate KDF salt/key after each successful unlock.
      const rotatedKdf = createKdf(VaultCrypto.KDF_ROUNDS);
      const rotatedKey = await deriveKeyFromKdf(masterPassword, rotatedKdf);
      const rotatedBundle = await encryptEntries(entries, rotatedKey, rotatedKdf);
      await writeBundle(rotatedBundle);

      return {
        entries,
        key: rotatedKey,
      };
    }

    const legacy = await getLegacy();
    if (!legacy.encrypted || !legacy.salt) {
      throw new Error("Vault does not exist.");
    }

    return migrateLegacyVault(masterPassword, legacy.encrypted, legacy.salt);
  }

  async function writeVault(entries, key) {
    const bundle = await getBundle();
    if (!bundle) {
      throw new Error("Vault is not initialized.");
    }

    const kdf = {
      iterations: Number(bundle.kdf?.iterations || VaultCrypto.KDF_ROUNDS),
      salt: String(bundle.kdf?.salt || ""),
    };

    const encryptedBundle = await encryptEntries(entries, key, kdf);
    await writeBundle(encryptedBundle);
  }

  async function readVault(key) {
    const bundle = await getBundle();
    if (bundle) {
      try {
        return await decryptBundle(bundle, key);
      } catch (_error) {
        return null;
      }
    }

    const legacy = await getLegacy();
    if (!legacy.encrypted || !legacy.salt) {
      return [];
    }

    try {
      const plainText = await VaultCrypto.openTextWithKey(legacy.encrypted, key);
      return parseEntries(plainText);
    } catch (_error) {
      return null;
    }
  }

  return {
    LEGACY_ENCRYPTED_VAULT_KEY,
    LEGACY_SALT_STORAGE_KEY,
    VAULT_BUNDLE_KEY,
    vaultExists,
    createVault,
    unlockVault,
    writeVault,
    readVault,
  };
})();
