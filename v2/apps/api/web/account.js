const byId = (id) => document.getElementById(id);
const say = (id, message) => { byId(id).textContent = message; };
const genericAction = "If the address is eligible, an email will be sent with next steps.";
const authHeaders = () => ({ Authorization: `Bearer ${sessionStorage.getItem("securelink.accessToken")}` });

async function refreshMFAStatus() {
  const token = sessionStorage.getItem("securelink.accessToken");
  if (!token) return;
  const response = await fetch("/auth/mfa", {
    headers: authHeaders(), credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) return;
  const status = await response.json();
  const note = byId("mfa-policy-note");
  note.hidden = !status.required;
  if (status.required) {
    const deadline = status.grace_expires_at ? new Date(status.grace_expires_at) : null;
    note.textContent = deadline && deadline > new Date()
      ? `Owners and admins must enable MFA by ${deadline.toLocaleString()}. Organization access will pause after this deadline.`
      : "MFA is required for owner/admin access. Enable it to continue using privileged organization features.";
  }
  byId("mfa-status").textContent = status.enabled
    ? status.can_disable
      ? "Two-factor authentication is enabled."
      : "Two-factor authentication is enabled and required for your organization role."
    : status.required
      ? "Two-factor authentication is not enabled yet."
      : "Two-factor authentication is not enabled.";
  byId("mfa-start").hidden = status.enabled;
  byId("mfa-rotation-start-form").hidden = !status.enabled;
  byId("mfa-disable-form").hidden = !status.enabled || !status.can_disable;
}

byId("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: byId("register-email").value,
      password: byId("register-password").value,
      organization_name: byId("organization").value,
    }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  say("register-status", response.ok
    ? "If the address is eligible, an email will be sent with verification steps."
    : "We could not create the account. Check the fields and try again.");
  if (response.ok) event.target.reset();
});

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: byId("login-email").value,
      password: byId("login-password").value,
      mfa_code: byId("login-mfa-code").value || null,
    }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("login-status", "Sign-in failed. Check your credentials and verify your email address.");
    return;
  }
  const session = await response.json();
  sessionStorage.setItem("securelink.accessToken", session.access_token);
  sessionStorage.setItem("securelink.organizationId", session.organization_id);
  event.target.reset();
  byId("sign-out").hidden = false;
  byId("dashboard-link").hidden = false;
  byId("login-mfa-code").value = "";
  await refreshMFAStatus();
  say("session-status", "You are signed in for this browser tab. Your access token stays in session storage.");
  say("login-status", "Signed in.");
});

byId("sign-out").addEventListener("click", async () => {
  const token = sessionStorage.getItem("securelink.accessToken");
  if (token) {
    try {
      await fetch("/auth/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch {
      // Clear local credentials even when the network is unavailable.
    }
  }
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  byId("sign-out").hidden = true;
  byId("dashboard-link").hidden = true;
  byId("mfa-start").hidden = true;
  byId("mfa-disable-form").hidden = true;
  byId("mfa-rotation-start-form").hidden = true;
  byId("mfa-enrollment").hidden = true;
  byId("mfa-rotation-enrollment").hidden = true;
  byId("mfa-recovery").hidden = true;
  byId("mfa-status").textContent = "";
  say("session-status", "You are signed out. The access token was revoked when the server was reachable.");
  say("login-status", "");
});

byId("invite-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = sessionStorage.getItem("securelink.accessToken");
  const organizationId = sessionStorage.getItem("securelink.organizationId");
  if (!token || !organizationId) {
    say("invite-status", "Sign in first. Only organization owners and admins can invite members.");
    return;
  }
  const response = await fetch(`/organizations/${encodeURIComponent(organizationId)}/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ email: byId("invite-email").value, role: byId("invite-role").value }),
    credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  say("invite-status", response.ok
    ? "If the account is eligible, an invitation will be sent."
    : "Invitation could not be sent. Check your role, account status, and organization access.");
  if (response.ok) event.target.reset();
});

byId("recovery-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetch("/auth/password/forgot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: byId("recovery-email").value }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  say("recovery-status", genericAction);
  event.target.reset();
});

byId("resend-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetch("/auth/verification/resend", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: byId("resend-email").value }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  say("resend-status", genericAction);
  event.target.reset();
});

if (sessionStorage.getItem("securelink.accessToken")) {
  byId("sign-out").hidden = false;
  byId("dashboard-link").hidden = false;
  say("session-status", "You are signed in for this browser tab.");
  refreshMFAStatus();
}

byId("mfa-start").addEventListener("click", async () => {
  const response = await fetch("/auth/mfa/enrollment", {
    method: "POST", headers: authHeaders(), credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("mfa-status", "Setup could not start. Sign in again and retry.");
    return;
  }
  const enrollment = await response.json();
  byId("mfa-secret").textContent = enrollment.secret;
  byId("mfa-enrollment").hidden = false;
  say("mfa-status", "Enrollment key expires in 15 minutes. Complete setup in your authenticator app.");
});

byId("mfa-confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/mfa/confirm", {
    method: "POST", headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ code: byId("mfa-confirm-code").value }),
    credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("mfa-status", "That code did not verify. Check your device clock and try again.");
    return;
  }
  const { recovery_codes: codes } = await response.json();
  const list = byId("mfa-recovery-codes");
  list.replaceChildren(...codes.map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  byId("mfa-recovery").hidden = false;
  byId("mfa-enrollment").hidden = true;
  byId("mfa-confirm-form").reset();
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  byId("sign-out").hidden = true;
  byId("dashboard-link").hidden = true;
  byId("mfa-start").hidden = true;
  byId("mfa-disable-form").hidden = true;
  byId("mfa-status").textContent = "Two-factor authentication enabled. All sessions were revoked; save these recovery codes, then sign in again.";
  say("session-status", "MFA was enabled and all previous sessions were revoked. Save your recovery codes, then sign in again.");
});

byId("mfa-rotation-start-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/mfa/rotation", {
    method: "POST", headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      password: byId("mfa-rotation-password").value,
      code: byId("mfa-rotation-current-code").value,
    }),
    credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("mfa-status", "Replacement could not start. Check your password and current authenticator or recovery code.");
    return;
  }
  const enrollment = await response.json();
  byId("mfa-rotation-secret").textContent = enrollment.secret;
  byId("mfa-rotation-enrollment").hidden = false;
  byId("mfa-rotation-password").value = "";
  byId("mfa-rotation-current-code").value = "";
  say("mfa-status", "Replacement key expires in 15 minutes. Your existing authenticator is still active.");
});

byId("mfa-rotation-confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/mfa/rotation/confirm", {
    method: "POST", headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ code: byId("mfa-rotation-confirm-code").value }),
    credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("mfa-status", "Replacement could not be confirmed. Check the new authenticator code and try before it expires.");
    return;
  }
  const { recovery_codes: codes } = await response.json();
  const list = byId("mfa-recovery-codes");
  list.replaceChildren(...codes.map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  byId("mfa-recovery").hidden = false;
  byId("mfa-rotation-enrollment").hidden = true;
  byId("mfa-rotation-confirm-form").reset();
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  byId("sign-out").hidden = true;
  byId("dashboard-link").hidden = true;
  byId("mfa-rotation-start-form").hidden = true;
  byId("mfa-disable-form").hidden = true;
  say("session-status", "Your authenticator was replaced and all sessions were revoked. Save these new recovery codes, then sign in again.");
  say("mfa-status", "Authenticator replaced. Previous recovery codes are no longer valid.");
});

byId("mfa-disable-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/auth/mfa/disable", {
    method: "POST", headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ password: byId("mfa-disable-password").value, code: byId("mfa-disable-code").value }),
    credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) {
    say("mfa-status", "MFA could not be disabled. Check your password and code.");
    return;
  }
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  byId("sign-out").hidden = true;
  byId("dashboard-link").hidden = true;
  byId("mfa-disable-form").hidden = true;
  byId("mfa-recovery").hidden = true;
  byId("mfa-status").textContent = "Two-factor authentication disabled. Your sessions were revoked; sign in again.";
});
