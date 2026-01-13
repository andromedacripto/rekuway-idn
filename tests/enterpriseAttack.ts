import axios from "axios";

const API = "https://rekuway-idn-mvp.vercel.app";

const client = axios.create({
  validateStatus: () => true, // 🔥 aceita qualquer status
});

async function createIdentity(level: string) {
  const res = await client.post(`${API}/identity/new`, {
    paranoiaLevel: level,
  });
  return res.data;
}

async function attack(id: string, attempts = 6) {
  for (let i = 1; i <= attempts; i++) {
    const res = await client.post(`${API}/identity/check`, {
      identityId: id,
      privateKey: `attacker-${i}`,
    });

    console.log(
      `Attempt ${i}:`,
      `HTTP ${res.status}`,
      `Action: ${res.data.action}`,
      `Remaining: ${res.data.remaining}`
    );

    if (res.data.action === "KILLED") {
      console.log("💀 Identity destroyed — attack neutralized");
      break;
    }
  }
}

(async () => {
  console.log("🔐 Rekuway IDN — Enterprise Attack Simulation");

  const identity = await createIdentity("high");
  console.log("ID:", identity.identity.id);

  await attack(identity.identity.id);
})();
