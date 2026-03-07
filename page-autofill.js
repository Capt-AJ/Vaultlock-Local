(() => {
  function isExpectedOrigin(expectedOrigin) {
    if (!expectedOrigin || typeof expectedOrigin !== "string") {
      return false;
    }

    try {
      if (window.location.protocol !== "https:") {
        return false;
      }
      return new URL(expectedOrigin).origin === window.location.origin;
    } catch (_error) {
      return false;
    }
  }

  function collectInputs(selectors) {
    const found = [];
    const seen = new Set();

    for (const selector of selectors) {
      for (const node of document.querySelectorAll(selector)) {
        if (!(node instanceof HTMLInputElement)) {
          continue;
        }

        if (seen.has(node) || node.disabled || node.readOnly || node.type === "hidden") {
          continue;
        }

        const box = node.getBoundingClientRect();
        const style = window.getComputedStyle(node);
        if (box.width === 0 || box.height === 0 || style.visibility === "hidden" || style.display === "none") {
          continue;
        }

        seen.add(node);
        found.push(node);
      }
    }

    return found;
  }

  function writeInputValue(input, value) {
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value");
    if (descriptor?.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function locatePasswordField() {
    return collectInputs([
      'input[type="password"]',
      'input[autocomplete="current-password"]',
      'input[autocomplete="password"]'
    ])[0] || null;
  }

  function locateIdentityField(passwordField) {
    const candidates = collectInputs([
      'input[autocomplete="username"]',
      'input[type="email"]',
      'input[name*="user" i]',
      'input[name*="mail" i]',
      'input[name*="login" i]',
      'input[id*="user" i]',
      'input[id*="mail" i]',
      'input[id*="login" i]',
      'input[placeholder*="email" i]',
      'input[placeholder*="user" i]'
    ]);

    if (!passwordField) {
      return candidates[0] || null;
    }

    const formMatch = candidates.find((candidate) => candidate.form && passwordField.form && candidate.form === passwordField.form);
    if (formMatch) {
      return formMatch;
    }

    const passwordTop = passwordField.getBoundingClientRect().top;
    return candidates.find((candidate) => candidate.getBoundingClientRect().top <= passwordTop) || candidates[0] || null;
  }

  function fillCredentials(username, password) {
    const passwordField = locatePasswordField();
    const identityField = locateIdentityField(passwordField);

    if (identityField) {
      writeInputValue(identityField, username);
    }

    if (passwordField) {
      writeInputValue(passwordField, password);
    }

    return Boolean(identityField || passwordField);
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "AUTOFILL_ACTIVE_PAGE") {
      return false;
    }

    if (!isExpectedOrigin(message.expectedOrigin)) {
      sendResponse({ success: false });
      return false;
    }

    const username = String(message.username ?? "");
    const password = String(message.password ?? "");

    // reject absurdly large values to avoid memory abuse
    if (username.length > 1024 || password.length > 1024) {
      sendResponse({ success: false });
      return false;
    }

    const success = fillCredentials(username, password);
    sendResponse({ success });
    return false;
  });
})();
