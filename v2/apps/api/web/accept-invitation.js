const status = document.querySelector("#status");
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);
if (!token) {
  status.textContent = "This invitation link is missing or invalid. Ask an organization owner to send a new invitation.";
} else {
  fetch("/auth/invitations/accept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  })
    .then((response) => {
      if (!response.ok) throw new Error("invitation_failed");
      status.textContent = "Invitation accepted. Sign in to access the organization.";
    })
    .catch(() => {
      status.textContent = "This invitation is invalid, expired, or already used. Ask an organization owner to send a new one.";
    });
}
