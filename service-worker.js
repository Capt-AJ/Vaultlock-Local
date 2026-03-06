chrome.runtime.onInstalled.addListener((details) => {
  console.info("VaultLock Local installed", {
    reason: details.reason,
    previousVersion: details.previousVersion ?? null,
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "HEALTHCHECK") {
    sendResponse({ ok: true, scope: "service-worker" });
    return;
  }

  return false;
});
