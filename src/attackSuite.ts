import axios from "axios";
import pLimit from "p-limit";
import { v4 as uuid } from "uuid";

const API_URL = "https://rekuway-idn-mvp.vercel.app";

/* ------------------ TYPES ------------------ */

type Identity = {
  id: string;
  privateKey: string;
};

/* ------------------ HELPERS ------------------ */

async function createIdentity(level: string): Promise<Identity> {
  const res = await axios.post(`${API_URL}/identity/new`, {
    paranoiaLevel: level,
  });
  return res.data;
}

async function checkIdentity(id: string, key: string) {
  try {
    const res = await axios.post(`${API_URL}/identity/check`, {
      identityId: id,
      privateKey: key,
    });
    return res.data;
  } catch (e: any) {
    return e.response?.data || null;
  }
}

function log(title: string) {
  console.log(`\n🔥 ${title}`);
}

/* =====================================================
   ATTACK 1 — MASSIVE PARALLEL RACE CONDITION
   Goal: break state consistency
===================================================== */

async function attackRaceCondition() {
  log("ATTACK 1 — RACE CONDITION (100 parallel requests)");

  const identity = await createIdentity("high");
  const limit = pLimit(50);

  const tasks = Array.from({ length: 100 }).map((_, i) =>
    limit(() =>
      checkIdentity(identity.id, `race-${i}-${uuid()}`)
    )
  );

  const results = await Promise.all(tasks);
  const killed = results.some(r => r?.action === "KILLED");

  console.log("Result:", killed ? "✅ KILLED" : "❌ SURVIVED");
}

/* =====================================================
   ATTACK 2 — DISTRIBUTED REPLAY WITH STALE KEYS
===================================================== */

async function attackReplayStorm() {
  log("ATTACK 2 — DISTRIBUTED REPLAY STORM");

  const identity = await createIdentity("medium");
  const valid = await checkIdentity(identity.id, identity.privateKey);

  console.log("Initial access:", valid?.action);

  // force regeneration
  for (let i = 0; i < 5; i++) {
    await checkIdentity(identity.id, `wrong-${i}`);
  }

  const replays = await Promise.all(
    Array.from({ length: 10 }).map(() =>
      checkIdentity(identity.id, identity.privateKey)
    )
  );

  const survived = replays.some(r => r?.action === "ALLOWED");

  console.log("Replay survived?", survived ? "❌ YES" : "✅ NO");
}

/* =====================================================
   ATTACK 3 — KEY ENTROPY PROBING (SMART BRUTE)
===================================================== */

async function attackEntropyProbe() {
  log("ATTACK 3 — ENTROPY PROBE");

  const identity = await createIdentity("low");

  let success = false;

  for (let i = 0; i < 30; i++) {
    const guess = identity.privateKey.slice(0, 10) + uuid().slice(0, 5);
    const res = await checkIdentity(identity.id, guess);

    if (res?.action === "ALLOWED") {
      success = true;
      break;
    }

    if (res?.action === "KILLED") break;
  }

  console.log("Entropy broken?", success ? "❌ YES" : "✅ NO");
}

/* =====================================================
   ATTACK 4 — DEADMAN BYPASS ATTEMPT
===================================================== */

async function attackDeadmanBypass() {
  log("ATTACK 4 — DEADMAN BYPASS");

  const identity = await createIdentity("deadman");

  console.log("Waiting deadman window...");
  await new Promise(r => setTimeout(r, 20000));

  const res = await checkIdentity(identity.id, identity.privateKey);

  console.log(
    "Deadman status:",
    res?.action === "KILLED" ? "✅ WORKED" : "❌ FAILED"
  );
}

/* =====================================================
   ATTACK 5 — LONG PERSISTENT ADVERSARY
===================================================== */

async function attackPersistentAdversary() {
  log("ATTACK 5 — PERSISTENT ADVERSARY (3 minutes)");

  const identity = await createIdentity("high");

  const start = Date.now();
  let killed = false;

  while (Date.now() - start < 180_000) {
    const res = await checkIdentity(identity.id, uuid());
    if (res?.action === "KILLED") {
      killed = true;
      break;
    }
    await new Promise(r => setTimeout(r, 1500));
  }

  console.log("Persistent attacker neutralized?", killed ? "✅ YES" : "❌ NO");
}

/* =====================================================
   EXECUTION
===================================================== */

async function run() {
  console.log("\n🔐 REKUWAY IDN — EXTREME ENTERPRISE PENTEST");

  await attackRaceCondition();
  await attackReplayStorm();
  await attackEntropyProbe();
  await attackDeadmanBypass();
  await attackPersistentAdversary();

  console.log("\n🏁 PENTEST FINISHED");
}

run();
