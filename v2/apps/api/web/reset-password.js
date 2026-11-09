const status = document.querySelector("#status");
const form = document.querySelector("#reset-form");
const password = document.querySelector("#password");
let token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);

if (token) {
  status.textContent = "Choose a new password for your account.";
  form.hidden = false;
} else {
  status.textContent = "This reset link is missing or invalid. Request a new one from the sign-in page.";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!token) return;
  const actionToken = token;
  token = null;
  form.hidden = true;
  status.textContent = "Updating your password…";
  try {
    const response = await fetch("/auth/password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: actionToken, new_password: password.value }),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error("reset_failed");
    password.value = "";
    status.textContent = "Your password was updated. You can now sign in.";
  } catch {
    password.value = "";
    status.textContent = "This reset link expired or was already used. Request a new one from the sign-in page.";
  }
});
