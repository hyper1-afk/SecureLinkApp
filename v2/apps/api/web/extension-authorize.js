const byId = (id) => document.getElementById(id);
const query = new URLSearchParams(window.location.search);
const request = {
  client_id: query.get("client_id"),
  redirect_uri: query.get("redirect_uri"),
  state: query.get("state"),
  code_challenge: query.get("code_challenge"),
  code_challenge_method: query.get("code_challenge_method"),
};
let accessToken = null;

function setStatus(id, message) {
  byId(id).textContent = message;
}

function validAuthorizationRequest() {
  return request.client_id === "securelink-chrome-extension"
    && request.code_challenge_method === "S256"
    && /^[A-Za-z0-9_-]{43}$/.test(request.code_challenge || "")
    && /^[A-Za-z0-9_-]{43,128}$/.test(request.state || "")
    && typeof request.redirect_uri === "string";
}

async function loadOrganizations() {
  const response = await fetch("/extension/oauth/organizations", {
    headers: { Authorization: `Bearer ${accessToken}` },
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok) throw new Error("Could not load organizations.");
  const result = await response.json();
  const select = byId("organization");
  select.replaceChildren();
  for (const organization of result.organizations) {
    const option = document.createElement("option");
    option.value = organization.id;
    option.textContent = `${organization.name} (${organization.role})`;
    select.append(option);
  }
  if (!result.organizations.length) {
    throw new Error("Your account does not have analyst access to an organization.");
  }
  byId("sign-in-panel").hidden = true;
  byId("consent-panel").hidden = false;
  setStatus("authorization-status", "Signed in. Review the requested access before approving.");
}

byId("sign-in-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("sign-in-status", "Signing in…");
  try {
    const credentials = {
      email: byId("email").value,
      password: byId("password").value,
      mfa_code: byId("mfa-code").value || null,
    };
    byId("password").value = "";
    byId("mfa-code").value = "";
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error("Sign-in failed. Check your credentials and verify your email.");
    const session = await response.json();
    accessToken = session.access_token;
    await loadOrganizations();
  } catch (error) {
    accessToken = null;
    setStatus("sign-in-status", error instanceof Error ? error.message : "Sign-in failed.");
  }
});

byId("approve-button").addEventListener("click", async () => {
  if (!accessToken || !validAuthorizationRequest()) return;
  byId("approve-button").disabled = true;
  try {
    const response = await fetch("/extension/oauth/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        ...request,
        organization_id: byId("organization").value,
      }),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error("SecureLink could not authorize this extension request.");
    const result = await response.json();
    accessToken = null;
    window.location.replace(result.redirect_url);
  } catch (error) {
    byId("approve-button").disabled = false;
    setStatus("authorization-status", error instanceof Error ? error.message : "Authorization failed.");
  }
});

byId("cancel-button").addEventListener("click", () => {
  accessToken = null;
  window.close();
});

if (!validAuthorizationRequest()) {
  byId("sign-in-panel").hidden = true;
  byId("consent-panel").hidden = true;
  setStatus("authorization-status", "This extension authorization request is invalid. Close this page and try again.");
}
