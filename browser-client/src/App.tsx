export default function App() {

  const bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljZGRkMS0yNjg1LTc0YWYtOTNhYi1hZjIwMDA1YWQ1YWIiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MzI0ODkwNywiaWF0IjoxNzczMjQ4MDA3fQ.Fu5kbsob65fb-aAvo_PFx7dJB2Jaq7hoqRX56nxPcM4";

  async function registerPasskey() {
    const res = await fetch(`http://localhost:8080/auth/passkey/register/options?bearer=${bearer}`, {
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

    await fetch(`http://localhost:8080/auth/passkey/register/verify?bearer=${bearer}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential)
    });

    console.log("passkey registered");
  }


  async function loginWithPasskey() {
    const res = await fetch(`http://localhost:8080/auth/passkey/authenticate/options`, {
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

    await fetch(`http://localhost:8080/auth/passkey/authenticate/verify`, {
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
