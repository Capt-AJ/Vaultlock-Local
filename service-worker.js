const SENSITIVE_STORAGE_KEYS = [
  "vault_bundle_v2",
  "vault_encrypted",
  "vault_salt",
];

function syncRemove(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.sync.remove(keys, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve();
    });
  });
}

async function scrubSyncStorage() {
  try {
    await syncRemove(SENSITIVE_STORAGE_KEYS);
  } catch (_error) {
    // Best effort only; avoid breaking extension startup.
  }
}

chrome.runtime.onInstalled.addListener((details) => {
  void scrubSyncStorage();
  console.info("VaultLock Local installed", {
    reason: details.reason,
    previousVersion: details.previousVersion ?? null,
  });
});

chrome.runtime.onStartup.addListener(() => {
  void scrubSyncStorage();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "sync") {
    return;
  }

  const changedSensitive = Object.keys(changes).some((key) => SENSITIVE_STORAGE_KEYS.includes(key));
  if (changedSensitive) {
    void scrubSyncStorage();
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false });
    return false;
  }

  if (message?.type === "HEALTHCHECK") {
    sendResponse({ ok: true, scope: "service-worker" });
    return false;
  }

  sendResponse({ ok: false });
  return false;
});
