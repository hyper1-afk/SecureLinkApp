const byId = (id) => document.getElementById(id);
const say = (id, message) => { byId(id).textContent = message; };
const genericAction = "If the address is eligible, an email will be sent with next steps.";

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
  say("session-status", "You are signed in for this browser tab. Your access token stays in session storage.");
  say("login-status", "Signed in.");
});

byId("sign-out").addEventListener("click", () => {
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  byId("sign-out").hidden = true;
  say("session-status", "You are signed out.");
  say("login-status", "");
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
  say("session-status", "You are signed in for this browser tab.");
}
