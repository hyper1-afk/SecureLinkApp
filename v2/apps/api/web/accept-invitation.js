const status = document.querySelector("#status");
const form = document.querySelector("#accept-form");
const password = document.querySelector("#invite-password");
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);
if (!token) {
  status.textContent = "This invitation link is missing or invalid. Ask an organization owner to send a new invitation.";
  form.hidden = true;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = { token };
  if (password.value) payload.password = password.value;
  status.textContent = "Accepting invitation…";
  try {
    const response = await fetch("/auth/invitations/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      if (data.detail === "Choose a password to finish setting up your invited account") {
        status.textContent = "Choose a password of at least 12 characters to finish your new account setup.";
      } else {
        status.textContent = "This invitation is invalid, expired, or already used. Ask an organization owner to send a new one.";
      }
      return;
    }
    form.hidden = true;
    status.textContent = "Invitation accepted. Sign in to access the organization.";
  } catch {
    status.textContent = "The invitation could not be accepted right now. Please try again.";
  }
});
