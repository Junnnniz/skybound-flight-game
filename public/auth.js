(() => {
  const $ = id => document.getElementById(id);
  const path = window.location.pathname;
  const params = new URLSearchParams(window.location.search);
  const panels = {
    login: $("login-form"),
    signup: $("signup-form"),
    resetRequest: $("reset-request-form"),
    reset: $("reset-form"),
    verify: $("verify-panel")
  };
  const message = $("auth-message");
  const submitButtons = document.querySelectorAll(".primary");
  let csrfToken = "";
  let accountConfig = null;

  function setMessage(text, kind = "") {
    message.textContent = text;
    message.className = `message${kind ? ` ${kind}` : ""}`;
  }

  function showPanel(name, title, subtitle, showTabs = false) {
    Object.entries(panels).forEach(([key, panel]) => { panel.hidden = key !== name; });
    $("form-title").textContent = title;
    $("form-subtitle").textContent = subtitle;
    $("auth-tabs").hidden = !showTabs;
    if (name === "login") $("login-tab").setAttribute("aria-current", "page");
    else $("login-tab").removeAttribute("aria-current");
    if (name === "signup") $("signup-tab").setAttribute("aria-current", "page");
    else $("signup-tab").removeAttribute("aria-current");
  }

  async function readApiResponse(response) {
    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("The account service is unavailable. Start the Skybound server and try again.");
    }
    if (!response.ok) throw new Error(result.error || "The request could not be completed.");
    return result;
  }

  async function getCsrfToken() {
    if (csrfToken) return csrfToken;
    const response = await fetch("/api/auth/csrf", { cache: "no-store" });
    const result = await readApiResponse(response);
    csrfToken = result.token;
    return csrfToken;
  }

  async function postJson(endpoint, body) {
    const token = await getCsrfToken();
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
      body: JSON.stringify(body)
    });
    const result = await readApiResponse(response);
    if (result.csrfToken) csrfToken = result.csrfToken;
    return result;
  }

  function handleError(error) {
    setMessage(error.message || "The request could not be completed. Try again.", "error");
    if (/verify your email/i.test(error.message)) $("resend-link").hidden = false;
  }

  function setBusy(form, busy) {
    form.querySelectorAll("button[type=submit]").forEach(button => {
      button.disabled = busy;
      button.dataset.originalText ||= button.textContent;
      button.textContent = busy ? "Please wait…" : button.dataset.originalText;
    });
  }

  document.querySelectorAll("[data-show-password]").forEach(button => {
    button.addEventListener("click", () => {
      const input = $(button.dataset.showPassword);
      input.type = input.type === "password" ? "text" : "password";
      button.textContent = input.type === "password" ? "Show" : "Hide";
    });
  });

  $("login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    setMessage("");
    try {
      await postJson("/api/auth/login", {
        email: $("login-email").value,
        password: $("login-password").value
      });
      window.location.assign("/");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(form, false);
    }
  });

  $("signup-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!accountConfig) {
      return setMessage("The account service is unavailable. Start the Skybound server and try again.", "error");
    }
    if ($("signup-password").value !== $("signup-confirm").value) {
      return setMessage("The passwords do not match.", "error");
    }
    const form = event.currentTarget;
    setBusy(form, true);
    setMessage("");
    try {
      const result = await postJson("/api/auth/register", {
        email: $("signup-email").value,
        password: $("signup-password").value,
        ageConfirmed: $("age-confirmed").checked,
        termsAccepted: $("terms-accepted").checked,
        privacyAcknowledged: $("privacy-acknowledged").checked,
        termsVersion: accountConfig.termsVersion,
        privacyVersion: accountConfig.privacyVersion
      });
      setMessage(result.message, "success");
      form.hidden = true;
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(form, false);
    }
  });

  $("resend-link").addEventListener("click", async () => {
    const email = $("login-email").value.trim();
    if (!email) return setMessage("Enter your email above first.", "error");
    try {
      const result = await postJson("/api/auth/resend-verification", { email });
      setMessage(result.message, "success");
    } catch (error) {
      handleError(error);
    }
  });

  $("reset-request-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    setMessage("");
    try {
      const result = await postJson("/api/auth/request-password-reset", { email: $("reset-email").value });
      setMessage(result.message, "success");
      form.hidden = true;
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(form, false);
    }
  });

  $("reset-form").addEventListener("submit", async event => {
    event.preventDefault();
    if ($("new-password").value !== $("new-password-confirm").value) {
      return setMessage("The passwords do not match.", "error");
    }
    const form = event.currentTarget;
    setBusy(form, true);
    setMessage("");
    try {
      const result = await postJson("/api/auth/reset-password", {
        token: params.get("token"),
        password: $("new-password").value
      });
      setMessage(result.message, "success");
      form.hidden = true;
      window.setTimeout(() => window.location.assign("/login"), 1800);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(form, false);
    }
  });

  $("verify-button").addEventListener("click", async () => {
    $("verify-button").disabled = true;
    setMessage("");
    try {
      const result = await postJson("/api/auth/verify", { token: params.get("token") });
      setMessage(result.message, "success");
      window.setTimeout(() => window.location.assign("/login?verified=1"), 1400);
    } catch (error) {
      handleError(error);
      $("verify-button").disabled = false;
    }
  });

  async function initialize() {
    if (window.location.protocol === "file:") {
      Object.values(panels).forEach(panel => { panel.hidden = true; });
      $("auth-tabs").hidden = true;
      $("local-file-notice").hidden = false;
      $("form-title").textContent = "Sign in";
      $("form-subtitle").textContent = "Welcome back. Your flight is ready.";
      return;
    }

    try {
      const response = await fetch("/api/auth/config", { cache: "no-store" });
      const config = await readApiResponse(response);
      accountConfig = config;
      if (!config.emailConfigured) {
        $("email-setup-notice").hidden = false;
        $("signup-form").querySelector('button[type="submit"]').disabled = true;
      }
    } catch (error) {
      $("signup-form").querySelector('button[type="submit"]').disabled = true;
      setMessage(error.message, "error");
    }

    if (path === "/signup") {
      showPanel("signup", "Create your account", "Join Skybound with your email address.", true);
    } else if (path === "/reset-password" && params.has("token")) {
      showPanel("reset", "Choose a new password", "Use at least 12 characters for your new password.");
    } else if (path === "/reset-password") {
      showPanel("resetRequest", "Reset your password", "We’ll email you a secure link to choose a new password.");
    } else if (path === "/verify") {
      showPanel("verify", "Verify your email", "Confirm your email address to activate your account.");
      if (!params.has("token")) {
        $("verify-button").disabled = true;
        setMessage("This verification link is missing its token. Request a new one from the sign-in page.", "error");
      }
    } else {
      showPanel("login", "Sign in", "Welcome back. Your flight is ready.", true);
      if (params.get("verified") === "1") setMessage("Email verified. You can now sign in.", "success");
    }
    if (!params.has("token") && (path === "/verify" || path === "/reset-password")) {
      submitButtons.forEach(button => { if (button.id === "verify-button") button.disabled = true; });
    }
  }

  initialize();
})();
