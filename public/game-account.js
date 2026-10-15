(() => {
  const email = document.getElementById("account-email");
  const logout = document.getElementById("logout-button");

  async function csrf() {
    const response = await fetch("/api/auth/csrf", { cache: "no-store" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Could not validate this session.");
    return result.token;
  }

  fetch("/api/auth/me", { cache: "no-store" })
    .then(async response => {
      if (response.status === 401) {
        window.location.replace("/login");
        return null;
      }
      if (!response.ok) throw new Error("Could not load your account.");
      return response.json();
    })
    .then(result => {
      if (result) email.textContent = result.user.email;
    })
    .catch(error => {
      console.error(error);
      email.textContent = "Account unavailable";
    });

  logout.addEventListener("click", async () => {
    logout.disabled = true;
    try {
      const token = await csrf();
      const response = await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": token }
      });
      if (!response.ok) throw new Error("Could not sign out. Please try again.");
      window.location.replace("/login");
    } catch (error) {
      console.error(error);
      logout.disabled = false;
      logout.textContent = "Retry sign out";
    }
  });
})();
