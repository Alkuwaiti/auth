export default function App() {

  async function registerPasskey() {
    const bearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljZDI4NC1mM2U3LTc5M2YtOTVmYS0zY2Q2YjZkYWM3NWYiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MzA1OTM1OSwiaWF0IjoxNzczMDU4NDU5fQ.gfjRTLP9u6Nw2lniQVC9Jl9z5W8YnkVqmswMqEkwvk0"

    const res = await fetch(`http://localhost:8080/auth/passkey/register/options?bearer=${bearer}`, {
      method: "POST",
      credentials: "include"
    });

    const options = await res.json();

    // Convert base64 → ArrayBuffer
    options.challenge = base64ToBuffer(options.challenge);
    options.user.id = base64ToBuffer(options.user.id);

    const credential = await navigator.credentials.create({
      publicKey: options
    });

    console.log("credential", credential);

    await fetch(`http://localhost:8080/auth/passkey/register/verify?bearer=${bearer}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential)
    });

  }

  return (
    <div style={{ padding: 40 }}>
      <button onClick={registerPasskey}>
        Register Passkey
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
