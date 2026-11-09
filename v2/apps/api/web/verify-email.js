const status = document.querySelector("#status");
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);

if (!token) {
  status.textContent = "This verification link is missing or invalid. Request a new one from the sign-in page.";
} else {
  fetch("/auth/verify-email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
  })
    .then((response) => {
      if (!response.ok) throw new Error("verification_failed");
      status.textContent = "Your email is verified. You can now sign in.";
    })
    .catch(() => {
      status.textContent = "This verification link has expired or was already used. Request a new one from the sign-in page.";
    });
}
