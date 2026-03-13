export default function App() {
  const domain = "http://localhost:8080"

  const bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljZTdhYS0yOGQ2LTc2ZDYtOWU5Ni1lMGFiOWUyMDhkN2EiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MzQxNTAxOCwiaWF0IjoxNzczNDE0MTE4fQ.-t2UFyvls7hhAB4Igdk9-qeRvDt006fRbZCSsGdTft0";

  async function registerPasskey() {
    const res = await fetch(`${domain}/auth/passkey/register/options?bearer=${bearer}`, {
      method: "POST",
      credentials: "include"
    });

    const options = await res.json();

    options.challenge = base64ToBuffer(options.challenge);
    options.user.id = base64ToBuffer(options.user.id);

    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c: any) => ({
        ...c,
        id: base64ToBuffer(c.id)
      }));
    }

    const credential = await navigator.credentials.create({
      publicKey: options
    });

    await fetch(`${domain}/auth/passkey/register/verify?bearer=${bearer}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential)
    });

    console.log("passkey registered");
  }


  async function loginWithPasskey() {
    const res = await fetch(`${domain}/auth/passkey/authenticate/options`, {
      method: "POST",
      credentials: "include"
    });

    const options = await res.json();

    options.challenge = base64ToBuffer(options.challenge);

    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c: any) => ({
        ...c,
        id: base64ToBuffer(c.id)
      }));
    }

    // STEP 2: get assertion from authenticator
    const credential = await navigator.credentials.get({
      publicKey: options
    });

    console.log("assertion", credential);

    await fetch(`${domain}/auth/passkey/authenticate/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential),
      credentials: "include"
    });

    console.log("authentication successful");
  }


  return (
    <div style={{ padding: 40 }}>
      <button onClick={registerPasskey}>
        Register Passkey
      </button>

      <br /><br />

      <button onClick={loginWithPasskey}>
        Login With Passkey
      </button>
    </div>
  );
}



function base64ToBuffer(base64: string) {
  const binary = atob(base64.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
