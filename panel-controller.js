// Security notes:
// - If malware, a keylogger, or browser compromise is present, secrets may be exposed while unlocked.
// - The master password is never stored and exists only in popup memory during the unlocked session.
// - Forgotten master passwords cannot be recovered because the vault is encrypted locally without a backup service.

(() => {
  const session = {
    // after derivation we only keep the CryptoKey; the raw password is cleared
    vaultKey: null,
    entries: [],
    searchText: "",
    editingId: null,
    clipboardTimer: null,
    autoLockTimer: null,
  };

  const strengthScale = [
    { label: "Very Weak", color: "#ef4444", width: "18%" },
    { label: "Weak", color: "#f97316", width: "36%" },
    { label: "Fair", color: "#eab308", width: "58%" },
    { label: "Strong", color: "#22c55e", width: "80%" },
    { label: "Very Strong", color: "#06b6d4", width: "100%" },
  ];

  const ui = {
    gate: document.getElementById("gate"),
    workspace: document.getElementById("workspace"),
    createView: document.getElementById("create-view"),
    unlockView: document.getElementById("unlock-view"),
    gateError: document.getElementById("gate-error"),
    createForm: document.getElementById("create-form"),
    unlockForm: document.getElementById("unlock-form"),
    createMaster: document.getElementById("create-master"),
    confirmMaster: document.getElementById("confirm-master"),
    unlockMaster: document.getElementById("unlock-master"),
    filterInput: document.getElementById("filter-input"),
    lockVault: document.getElementById("lock-vault"),
    resultsMeta: document.getElementById("results-meta"),
    recordList: document.getElementById("record-list"),
    recordForm: document.getElementById("record-form"),
    recordId: document.getElementById("record-id"),
    editorTitle: document.getElementById("editor-title"),
    abortEdit: document.getElementById("abort-edit"),
    siteName: document.getElementById("site-name"),
    accountName: document.getElementById("account-name"),
    secretValue: document.getElementById("secret-value"),
    extraNotes: document.getElementById("extra-notes"),
    toggleSecret: document.getElementById("toggle-secret"),
    editorStatus: document.getElementById("editor-status"),
    strengthFill: document.getElementById("strength-fill"),
    strengthCopy: document.getElementById("strength-copy"),
    lengthRange: document.getElementById("length-range"),
    lengthBadge: document.getElementById("length-badge"),
    optLower: document.getElementById("opt-lower"),
    optUpper: document.getElementById("opt-upper"),
    optDigits: document.getElementById("opt-digits"),
    optSymbols: document.getElementById("opt-symbols"),
    generatorOutput: document.getElementById("generator-output"),
    makePassword: document.getElementById("make-password"),
    copyGenerated: document.getElementById("copy-generated"),
    generatorStatus: document.getElementById("generator-status"),
  };

  function showAuthScreen(mode) {
    ui.gate.classList.remove("hidden");
    ui.workspace.classList.add("hidden");
    ui.gateError.textContent = "";
    ui.createView.classList.toggle("hidden", mode !== "create");
    ui.unlockView.classList.toggle("hidden", mode !== "unlock");
  }

  function showVaultScreen() {
    ui.gate.classList.add("hidden");
    ui.workspace.classList.remove("hidden");
  }

  function resetEditor() {
    session.editingId = null;
    ui.recordForm.reset();
    ui.recordId.value = "";
    ui.editorTitle.textContent = "New login";
    ui.abortEdit.classList.add("hidden");
    ui.secretValue.type = "password";
    ui.toggleSecret.textContent = "Show";
    ui.editorStatus.textContent = "";
    refreshStrength("");
  }

  function eraseUnlockedState() {
    session.vaultKey = null; // drop reference to the derived key
    session.entries = [];
    session.searchText = "";
    session.editingId = null;
  }

  function clearAllForms() {
    ui.createForm.reset();
    ui.unlockForm.reset();
    ui.filterInput.value = "";
    ui.generatorOutput.value = "";
    ui.generatorStatus.textContent = "";
    ui.editorStatus.textContent = "";
    resetEditor();
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function makeId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  // constant-time string comparison to avoid leaking information via timing attacks
  function secureCompare(a, b) {
    const encoder = new TextEncoder();
    const ua = encoder.encode(a);
    const ub = encoder.encode(b);
    if (ua.length !== ub.length) return false;
    let diff = 0;
    for (let i = 0; i < ua.length; i++) {
      diff |= ua[i] ^ ub[i];
    }
    return diff === 0;
  }

  function escapeMarkup(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function getVisibleEntries() {
    const search = session.searchText.trim().toLowerCase();
    const sorted = [...session.entries].sort((left, right) => left.site.localeCompare(right.site));

    if (!search) {
      return sorted;
    }

    return sorted.filter((entry) => {
      return entry.site.toLowerCase().includes(search) || entry.username.toLowerCase().includes(search);
    });
  }

  function drawEntries() {
    const visible = getVisibleEntries();
    ui.resultsMeta.textContent = `${visible.length} shown / ${session.entries.length} total`;

    if (visible.length === 0) {
      ui.recordList.innerHTML = '<div class="empty-card">No entries match the current filter.</div>';
      return;
    }

    ui.recordList.innerHTML = visible
      .map((entry) => {
        const noteCopy = entry.notes ? '<span title="' + escapeMarkup(entry.notes) + '">Notes saved</span>' : "<span>No notes</span>";
        return `
          <article class="record-card" data-id="${escapeMarkup(entry.id)}">
            <div class="record-top">
              <div>
                <h3>${escapeMarkup(entry.site)}</h3>
                <p class="meta-text">${escapeMarkup(entry.username)}</p>
              </div>
              <span class="inline-status meta-text" data-status-for="${escapeMarkup(entry.id)}"></span>
            </div>
            <div class="record-meta">
              <span>Updated ${escapeMarkup(new Date(entry.updatedAt).toLocaleString())}</span>
              ${noteCopy}
            </div>
            <div class="button-row wrap-row">
              <button type="button" class="btn btn-secondary btn-small" data-action="copy" data-id="${escapeMarkup(entry.id)}">Copy</button>
              <button type="button" class="btn btn-secondary btn-small" data-action="fill" data-id="${escapeMarkup(entry.id)}">Autofill current tab</button>
              <button type="button" class="btn btn-ghost btn-small" data-action="edit" data-id="${escapeMarkup(entry.id)}">Edit</button>
              <button type="button" class="btn btn-danger btn-small" data-action="remove" data-id="${escapeMarkup(entry.id)}">Delete</button>
            </div>
          </article>
        `;
      })
      .join("");
  }

  function scoreSecret(secret) {
    if (!secret || secret.length < 8) {
      return 0;
    }

    let score = 0;
    if (secret.length >= 8) score += 1;
    if (secret.length >= 12) score += 1;
    if (secret.length >= 16) score += 1;
    if (/[a-z]/.test(secret)) score += 1;
    if (/[A-Z]/.test(secret)) score += 1;
    if (/\d/.test(secret)) score += 1;
    if (/[^A-Za-z0-9]/.test(secret)) score += 1;

    if (score <= 2) return 0;
    if (score === 3) return 1;
    if (score === 4) return 2;
    if (score <= 6) return 3;
    return 4;
  }

  function refreshStrength(secret) {
    const state = strengthScale[scoreSecret(secret)];
    ui.strengthFill.style.width = state.width;
    ui.strengthFill.style.backgroundColor = state.color;
    ui.strengthCopy.textContent = `Strength: ${state.label}`;
  }

  function selectedGeneratorOptions() {
    return {
      length: Number(ui.lengthRange.value),
      lower: ui.optLower.checked,
      upper: ui.optUpper.checked,
      digits: ui.optDigits.checked,
      symbols: ui.optSymbols.checked,
    };
  }

  function buildPassword({ length, lower, upper, digits, symbols }) {
    // enforce sane limits
    length = Math.min(Math.max(length, 8), 128);
    const sourceSets = [];
    if (lower) sourceSets.push("abcdefghijklmnopqrstuvwxyz");
    if (upper) sourceSets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (digits) sourceSets.push("0123456789");
    if (symbols) sourceSets.push("!@#$%^&*()-_=+[]{};:,.?/|~");

    if (sourceSets.length === 0) {
      throw new Error("Select at least one character group.");
    }

    const merged = sourceSets.join("");
    const output = [];

    for (const set of sourceSets) {
      output.push(set[randomIndex(set.length)]);
    }

    while (output.length < length) {
      output.push(merged[randomIndex(merged.length)]);
    }

    for (let i = output.length - 1; i > 0; i -= 1) {
      const j = randomIndex(i + 1);
      [output[i], output[j]] = [output[j], output[i]];
    }

    return output.join("");
  }

  function randomIndex(limit) {
    return crypto.getRandomValues(new Uint32Array(1))[0] % limit;
  }

  async function saveSessionEntries() {
    if (!session.vaultKey) {
      throw new Error("Vault key unavailable; re‑unlock required.");
    }
    await VaultRepository.writeVault(session.entries, session.vaultKey);
  }

  function flashRowStatus(entryId, message, tone) {
    const node = ui.recordList.querySelector(`[data-status-for="${CSS.escape(entryId)}"]`);
    if (!node) {
      return;
    }

    node.textContent = message;
    node.classList.toggle("status-success", tone === "success");
    node.classList.toggle("status-error", tone === "error");

    setTimeout(() => {
      node.textContent = "";
      node.classList.remove("status-success", "status-error");
    }, 2500);
  }

  async function armClipboardAutoClear() {
    if (session.clipboardTimer) {
      clearTimeout(session.clipboardTimer);
    }

    // clear the clipboard after a short interval; shorter reduces exposure
    session.clipboardTimer = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
      } catch (_error) {
        // ignore any errors (permissions, focus, etc.)
      }
    }, 10000); // 10 seconds
  }

  async function copySecretText(text) {
    await navigator.clipboard.writeText(text);
    await armClipboardAutoClear();
  }

  function getActiveTab() {
    return new Promise((resolve, reject) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        resolve(tabs[0] ?? null);
      });
    });
  }

  function messageTab(tabId, payload) {
    return new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, payload, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        resolve(response);
      });
    });
  }

  async function fillActivePage(entry) {
    const tab = await getActiveTab();
    if (!tab?.id) {
      throw new Error("No active tab available.");
    }

    const response = await messageTab(tab.id, {
      type: "AUTOFILL_ACTIVE_PAGE",
      username: entry.username,
      password: entry.password,
    });

    if (!response?.success) {
      throw new Error("No login fields detected on the active page.");
    }
  }

  function beginEdit(entry) {
    session.editingId = entry.id;
    ui.recordId.value = entry.id;
    ui.editorTitle.textContent = "Edit login";
    ui.abortEdit.classList.remove("hidden");
    ui.siteName.value = entry.site;
    ui.accountName.value = entry.username;
    ui.secretValue.value = entry.password;
    ui.extraNotes.value = entry.notes ?? "";
    ui.editorStatus.textContent = "Editing existing entry.";
    refreshStrength(entry.password);
  }

  async function onRecordClick(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) {
      return;
    }

    const entry = session.entries.find((item) => item.id === button.dataset.id);
    if (!entry) {
      return;
    }

    try {
      switch (button.dataset.action) {
        case "copy":
          await copySecretText(entry.password);
          flashRowStatus(entry.id, "Copied", "success");
          break;
        case "fill":
          await fillActivePage(entry);
          flashRowStatus(entry.id, "Autofilled", "success");
          break;
        case "edit":
          beginEdit(entry);
          break;
        case "remove":
          session.entries = session.entries.filter((item) => item.id !== entry.id);
          await saveSessionEntries();
          if (session.editingId === entry.id) {
            resetEditor();
          }
          drawEntries();
          break;
        default:
          break;
      }
    } catch (error) {
      flashRowStatus(entry.id, error.message || "Action failed.", "error");
    }
  }

  async function createVault(event) {
    event.preventDefault();
    const candidate = ui.createMaster.value;
    const confirmation = ui.confirmMaster.value;

    if (candidate.length < 8) {
      ui.gateError.textContent = "Use at least 8 characters for the master password.";
      return;
    }

    if (!secureCompare(candidate, confirmation)) {
      ui.gateError.textContent = "Master passwords do not match.";
      return;
    }

    session.vaultKey = await VaultRepository.deriveKey(candidate);
    session.entries = [];
    await VaultRepository.writeVault(session.entries, session.vaultKey);
    clearAllForms();
    showVaultScreen();
    drawEntries();
    resetAutoLockTimer();
  }

  async function unlockVault(event) {
    event.preventDefault();
    const candidate = ui.unlockMaster.value;

    if (!candidate) {
      ui.gateError.textContent = "Enter the master password.";
      return;
    }

    // derive key first, then try decrypting vault; we need the key even if decryption fails
    const key = await VaultRepository.deriveKey(candidate);
    const loaded = await VaultRepository.readVault(key);
    if (loaded === null) {
      ui.gateError.textContent = "Incorrect master password or corrupted vault";
      ui.unlockMaster.select();
      return;
    }

    session.vaultKey = key;
    session.entries = loaded;
    ui.unlockForm.reset();
    showVaultScreen();
    drawEntries();
    resetAutoLockTimer();
  }

  async function saveRecord(event) {
    event.preventDefault();

    const site = ui.siteName.value.trim();
    const username = ui.accountName.value.trim();
    const password = ui.secretValue.value;
    const notes = ui.extraNotes.value.trim();

    // simple length bounds to avoid unbounded storage abuse.
    if (site.length === 0 || username.length === 0 || password.length === 0) {
      ui.editorStatus.textContent = "Site, username, and password are required.";
      return;
    }
    if (site.length > 256 || username.length > 256 || password.length > 256) {
      ui.editorStatus.textContent = "Field values are too long.";
      return;
    }

    const foundIndex = session.entries.findIndex((entry) => entry.id === session.editingId);
    if (foundIndex >= 0) {
      session.entries[foundIndex] = {
        ...session.entries[foundIndex],
        site,
        username,
        password,
        notes,
        updatedAt: nowIso(),
      };
      ui.editorStatus.textContent = "Entry updated.";
    } else {
      const timestamp = nowIso();
      session.entries.push({
        id: makeId(),
        site,
        username,
        password,
        notes,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      ui.editorStatus.textContent = "Entry saved.";
    }

    await saveSessionEntries();
    resetEditor();
    drawEntries();
  }

  async function copyGeneratedPassword() {
    if (!ui.generatorOutput.value) {
      ui.generatorStatus.textContent = "Generate a password first.";
      return;
    }

    await copySecretText(ui.generatorOutput.value);
    ui.generatorStatus.textContent = "Generated password copied.";
  }

  function generateIntoForm() {
    try {
      const password = buildPassword(selectedGeneratorOptions());
      ui.generatorOutput.value = password;
      ui.secretValue.value = password;
      refreshStrength(password);
      ui.generatorStatus.textContent = "Generated password inserted into the form.";
    } catch (error) {
      ui.generatorStatus.textContent = error.message || "Could not generate a password.";
    }
  }

  async function relockVault() {
    clearAllForms();
    eraseUnlockedState();
    drawEntries();
    const exists = await VaultRepository.vaultExists();
    showAuthScreen(exists ? "unlock" : "create");
    // stop auto-lock timer while locked
    if (session.autoLockTimer) {
      clearTimeout(session.autoLockTimer);
      session.autoLockTimer = null;
    }
  }

  // start-up logic includes auto-lock event registration
  async function boot() {
    ui.lengthBadge.textContent = ui.lengthRange.value;
    refreshStrength("");
    const exists = await VaultRepository.vaultExists();
    showAuthScreen(exists ? "unlock" : "create");
    registerAutoLockEvents();
  }

  ui.createForm.addEventListener("submit", (event) => {
    createVault(event).catch((error) => {
      ui.gateError.textContent = error.message || "Unable to create the vault.";
    });
  });

  // activity resets the auto-lock timer when the vault is unlocked
  function resetAutoLockTimer() {
    if (session.autoLockTimer) {
      clearTimeout(session.autoLockTimer);
    }
    // five minute inactivity lock
    session.autoLockTimer = setTimeout(() => {
      relockVault().catch(() => {});
    }, 5 * 60 * 1000);
  }

  function registerAutoLockEvents() {
    const events = ["click", "input", "keydown", "mousemove"];
    events.forEach((evt) => {
      document.addEventListener(evt, resetAutoLockTimer, { passive: true });
    });

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") {
        relockVault().catch(() => {});
      }
    });
  }

  ui.unlockForm.addEventListener("submit", (event) => {
    unlockVault(event).catch((error) => {
      ui.gateError.textContent = error.message || "Unable to unlock the vault.";
    });
  });

  ui.recordForm.addEventListener("submit", (event) => {
    saveRecord(event).catch((error) => {
      ui.editorStatus.textContent = error.message || "Unable to save the entry.";
    });
  });

  ui.recordList.addEventListener("click", (event) => {
    onRecordClick(event);
  });

  ui.filterInput.addEventListener("input", (event) => {
    session.searchText = event.target.value;
    drawEntries();
  });

  ui.lockVault.addEventListener("click", () => {
    relockVault().catch((error) => {
      ui.gateError.textContent = error.message || "Unable to lock the vault.";
    });
  });

  ui.secretValue.addEventListener("input", (event) => {
    refreshStrength(event.target.value);
  });

  ui.toggleSecret.addEventListener("click", () => {
    const isVisible = ui.secretValue.type === "text";
    ui.secretValue.type = isVisible ? "password" : "text";
    ui.toggleSecret.textContent = isVisible ? "Show" : "Hide";
  });

  ui.abortEdit.addEventListener("click", () => {
    resetEditor();
    ui.editorStatus.textContent = "Edit cancelled.";
  });

  ui.lengthRange.addEventListener("input", () => {
    ui.lengthBadge.textContent = ui.lengthRange.value;
  });

  ui.makePassword.addEventListener("click", () => {
    generateIntoForm();
  });

  ui.copyGenerated.addEventListener("click", () => {
    copyGeneratedPassword().catch((error) => {
      ui.generatorStatus.textContent = error.message || "Unable to copy generated password.";
    });
  });

  boot().catch((error) => {
    ui.gateError.textContent = error.message || "Unable to initialize the extension.";
  });
})();
