// Hourly anchor: fetch the Giveaway Draw commitment-log head and append it to anchors/.
// - If the API is unreachable or returns something unexpected: log a notice and exit 0 (no commit).
// - If the new head does not extend the last anchored head (history rewritten): record an alert
//   and exit 1, because that is exactly what this repository exists to catch.
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { logHash } from "../../verify.mjs";

const SOURCE = process.env.SOURCE || "https://draw.surveydraw.com.au/api/chain/head";
const base = new URL(SOURCE).origin;
const out = (k, v) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
const skip = (why) => {
  console.log(`::notice::anchor skipped: ${why}`);
  out("changed", "false");
  process.exit(0);
};

async function getJson(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { accept: "application/json", "user-agent": "giveaway-verify-anchor" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

let head;
try {
  head = await getJson(SOURCE);
} catch (e) {
  skip(`could not fetch ${SOURCE} (${e.message})`);
}
if (head.empty || head.seq === 0) skip("log is empty");

// Validate shape and that `line` is the canonical payload it claims to be.
const hex64 = /^[0-9a-f]{64}$/;
if (typeof head.line !== "string" || !hex64.test(head.log_hash ?? "") || !Number.isInteger(head.seq)) skip("unexpected response shape");
const line = JSON.parse(head.line);
if (line.v !== 1 || line.log !== "giveaway-draw" || line.seq !== head.seq || line.log_hash !== head.log_hash) skip("line does not match the response");
const lineSha = createHash("sha256").update(head.line, "utf8").digest("hex");
if (head.line_sha256 && head.line_sha256 !== lineSha) skip("line_sha256 mismatch");

const latestPath = "anchors/latest.json";
const prev = existsSync(latestPath) ? JSON.parse(readFileSync(latestPath, "utf8")) : null;

function alert(reason) {
  const entry = JSON.stringify({ detected_at: new Date().toISOString(), reason, previous: prev, received: line });
  appendFileSync("anchors/ALERTS.jsonl", entry + "\n");
  console.log(`::error::${reason}`);
  out("changed", "true");
  out("alert", "true");
  process.exit(1);
}

if (prev) {
  if (line.seq === prev.seq) {
    if (line.log_hash !== prev.log_hash) alert(`log head #${line.seq} changed hash (${prev.log_hash} → ${line.log_hash})`);
    skip(`no new commitments since #${prev.seq}`);
  }
  if (line.seq < prev.seq) alert(`log head went backwards (#${prev.seq} → #${line.seq})`);
  // The new head must extend the anchored one: re-link every entry since the last anchor.
  let expectPrev = prev.log_hash;
  for (let from = prev.seq + 1; from <= line.seq; from += 1000) {
    let slice;
    try {
      slice = await getJson(`${base}/api/chain?from=${from}&to=${Math.min(line.seq, from + 999)}`);
    } catch (e) {
      skip(`could not fetch the chain slice from #${from} (${e.message})`);
    }
    for (const e of slice.entries ?? []) {
      if (e.prev_log_hash !== expectPrev) alert(`entry #${e.seq} does not link to the anchored head`);
      if (logHash(e.prev_log_hash, e.commitment, e.seq, e.committed_at) !== e.log_hash) alert(`entry #${e.seq} has a bad log_hash`);
      expectPrev = e.log_hash;
    }
  }
  if (expectPrev !== line.log_hash) alert("chain slice does not end at the reported head");
}

const now = new Date();
const dir = `anchors/${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
mkdirSync(dir, { recursive: true });
appendFileSync(`${dir}/${String(now.getUTCDate()).padStart(2, "0")}.jsonl`, head.line + "\n");
writeFileSync(latestPath, JSON.stringify(line, null, 2) + "\n");
console.log(`anchored #${line.seq} ${line.log_hash}`);
out("changed", "true");
out("seq", String(line.seq));
