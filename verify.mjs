#!/usr/bin/env node
// verify.mjs: independent verifier for Giveaway Draw certificates (gd-v1 / canon-v1).
// MIT licence. Node 20+. No dependencies; if @noble/curves is installed it also checks the drand
// BLS signature against the pinned quicknet public key.
//
//   node verify.mjs <draw-id | certificate-url> [--entries list.txt | --csv list.csv [--column Name] [--no-header] [--handle-column H]]
//                   [--base https://draw.surveydraw.com.au] [--record draw.json] [--offline] [--json]
//
// It re-implements the published spec (https://draw.surveydraw.com.au/spec/gd-v1 and /spec/canon-v1)
// rather than reusing the server's code, so it is a genuine second implementation.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const QUICKNET = Object.freeze({
  hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  public_key:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  genesis_time: 1692803367,
  period: 3,
});
const DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const RELAYS = ["https://api.drand.sh", "https://drand.cloudflare.com", "https://api2.drand.sh", "https://api3.drand.sh"];
const MAX_ENTRY_LENGTH = 200;

// ---- bytes ---------------------------------------------------------------------------------

const enc = new TextEncoder();
export const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
export const hex = (b) => Buffer.from(b).toString("hex");
export const unhex = (s) => {
  if (typeof s !== "string" || !/^([0-9a-f]{2})*$/i.test(s)) throw new Error(`bad hex: ${s}`);
  return new Uint8Array(Buffer.from(s, "hex"));
};
const u64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
};

// ---- canon-v1 ------------------------------------------------------------------------------

const INVISIBLE = /[​⁠﻿]/g;
const WS = /\p{White_Space}+/gu;
const HANDLE = /@[\p{L}\p{N}_.]+/u;

export function canonLine(s) {
  return s.replace(INVISIBLE, "").normalize("NFC").replace(WS, " ").trim();
}

const splitLines = (t) => t.replace(/\r\n?/g, "\n").split("\n");

function dedupeKey(mode, entry, handle) {
  if (mode === "exact") return entry;
  if (mode === "case_insensitive") return entry.toLowerCase();
  // per_handle
  let h;
  if (handle !== undefined) {
    h = canonLine(handle);
    if (h === "") h = entry;
  } else {
    const m = HANDLE.exec(entry);
    h = m ? m[0] : entry;
  }
  return h.replace(/^@/, "").toLowerCase();
}

function finish(raw, dedupe) {
  if (!["none", "exact", "case_insensitive", "per_handle"].includes(dedupe)) throw new Error(`unknown dedupe mode ${dedupe}`);
  const seen = new Set();
  const entries = [];
  let blank = 0;
  let dupes = 0;
  for (const r of raw) {
    if (!r.text.isWellFormed()) throw new Error("an entry contains an unpaired surrogate");
    const e = canonLine(r.text);
    if (e === "") {
      blank++;
      continue;
    }
    if (e.length > MAX_ENTRY_LENGTH) throw new Error(`an entry is longer than ${MAX_ENTRY_LENGTH} characters`);
    if (dedupe !== "none") {
      const k = dedupeKey(dedupe, e, r.handle);
      if (seen.has(k)) {
        dupes++;
        continue;
      }
      seen.add(k);
    }
    entries.push(e);
  }
  const file = entries.length ? entries.join("\n") + "\n" : "";
  return { entries, file, entries_hash: hex(sha256(enc.encode(file))), received: raw.length, blank, dupes };
}

/** Pasted list (array of strings). Items containing line breaks are split. */
export function canonicaliseList(items, dedupe) {
  return finish(items.flatMap((i) => splitLines(i)).map((text) => ({ text })), dedupe);
}

export function decodeStrict(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/** RFC 4180, LF-normalised input. */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let q = false;
  let started = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          q = false;
          const n = text[i + 1];
          if (n !== undefined && n !== "," && n !== "\n") throw new Error(`CSV: unexpected character after closing quote in row ${rows.length + 1}`);
        }
      } else field += c;
    } else if (c === '"' && !started) {
      q = true;
      started = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
      started = false;
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      started = false;
    } else {
      field += c;
      started = true;
    }
  }
  if (q) throw new Error("CSV: a quoted field is never closed");
  if (started || field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function column(spec, header, what) {
  if (spec === undefined || String(spec).trim() === "") return 0;
  const s = String(spec).trim();
  if (/^\d+$/.test(s)) {
    if (Number(s) < 1) throw new Error(`${what} column numbers start at 1`);
    return Number(s) - 1;
  }
  if (!header) throw new Error(`${what} column '${s}' given by name but the CSV has no header`);
  const want = canonLine(s).toLowerCase();
  const i = header.findIndex((h) => canonLine(h).toLowerCase() === want);
  if (i < 0) throw new Error(`${what} column '${s}' not found in the CSV header`);
  return i;
}

/** Uploaded file (exact bytes). opts: { format: "txt"|"csv", dedupe, column, header (default true), handleColumn } */
export function canonicaliseFile(bytes, opts) {
  let t = decodeStrict(bytes);
  if (t.startsWith("﻿")) t = t.slice(1);
  if (opts.format === "txt") {
    const lines = splitLines(t);
    if (lines.length > 1 && lines.at(-1) === "") lines.pop();
    return finish(lines.map((text) => ({ text })), opts.dedupe);
  }
  const rows = parseCsv(t.replace(/\r\n?/g, "\n"));
  const hasHeader = opts.header ?? true;
  const header = hasHeader ? rows[0] : undefined;
  const body = hasHeader ? rows.slice(1) : rows;
  const col = column(opts.column, header, "Entry");
  const hcol = opts.dedupe === "per_handle" && opts.handleColumn !== undefined ? column(opts.handleColumn, header, "Handle") : undefined;
  return finish(body.map((r) => ({ text: r[col] ?? "", handle: hcol !== undefined ? (r[hcol] ?? "") : undefined })), opts.dedupe);
}

// ---- gd-v1 ---------------------------------------------------------------------------------

export function roundAt(ms, chain = QUICKNET) {
  const t = ms / 1000;
  return t < chain.genesis_time ? 0 : Math.floor((t - chain.genesis_time) / chain.period) + 1;
}
export const roundTimeMs = (r, chain = QUICKNET) => (chain.genesis_time + (r - 1) * chain.period) * 1000;
export const targetRound = (ms, chain = QUICKNET) => roundAt(ms, chain) + 2;

export function commitment(r) {
  const s = [
    "gd-v1",
    "commit",
    r.draw_id,
    r.entries_hash,
    r.entry_count,
    r.dedupe,
    r.num_winners,
    r.num_alternates,
    `quicknet:${r.chain_hash}`,
    r.target_round,
    r.committed_at,
  ].join("|");
  return hex(sha256(enc.encode(s)));
}

export function logHash(prev, commitmentHex, seq, committedAt) {
  return hex(sha256(unhex(prev), unhex(commitmentHex), enc.encode(`${seq}|${committedAt}`)));
}

export function select(entriesHashHex, drandRandomnessHex, n, w, a) {
  const seed = sha256(unhex(entriesHashHex), unhex(drandRandomnessHex));
  const label = enc.encode("gd-v1");
  let block = new Uint8Array(0);
  let pos = 0;
  let counter = 0n;
  const byte = () => {
    if (pos >= block.length) {
      block = sha256(seed, label, u64(counter++));
      pos = 0;
    }
    return block[pos++];
  };
  const u32 = () => ((byte() << 24) | (byte() << 16) | (byte() << 8) | byte()) >>> 0;
  const uniform = (m) => {
    const limit = Math.floor(2 ** 32 / m) * m;
    for (;;) {
      const u = u32();
      if (u < limit) return u % m;
    }
  };
  if (!(w >= 1 && a >= 0 && w + a <= n)) throw new Error("invalid counts");
  const idx = Array.from({ length: n }, (_, i) => i);
  for (let i = 0; i < w + a; i++) {
    const j = i + uniform(n - i);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  return { final_randomness: hex(seed), winners: idx.slice(0, w), alternates: idx.slice(w, w + a) };
}

// ---- drand ---------------------------------------------------------------------------------

/** BLS check with @noble/curves when available; returns true/false, or null if the library isn't installed. */
export async function blsVerify(signatureHex, round, chain = QUICKNET) {
  let bls;
  try {
    ({ bls12_381: bls } = await import("@noble/curves/bls12-381.js"));
  } catch {
    return null;
  }
  try {
    const s = bls.shortSignatures;
    return s.verify(unhex(signatureHex), s.hash(sha256(u64(round)), DST), unhex(chain.public_key));
  } catch {
    return false;
  }
}

async function getJson(url, timeoutMs = 6000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

/** Fetch round R from independent relays (v1 API). Returns the relays that answered and their signatures. */
export async function fetchRound(round, relays = RELAYS, chainHash = QUICKNET.hash) {
  const out = [];
  await Promise.all(
    relays.map(async (base) => {
      try {
        const j = await getJson(`${base}/${chainHash}/public/${round}`);
        if (j.round === round && typeof j.signature === "string") out.push({ relay: base, signature: j.signature.toLowerCase() });
      } catch {
        /* relay down: ignored */
      }
    }),
  );
  return out;
}

// ---- verification --------------------------------------------------------------------------

/**
 * Verify a public draw record (the /d/{id}.json document). `entries` (optional) is a canonicalised
 * list from canonicaliseList/canonicaliseFile. `relaySignatures` (optional) are signatures for the
 * record's round fetched from relays. Returns { checks, verdict, recomputed }.
 */
export async function verifyRecord(record, { entries, relaySignatures, logEntry, chain = QUICKNET } = {}) {
  const checks = [];
  const add = (name, pass, detail) => checks.push({ name, pass, detail });
  if (record.status === "void") {
    add("record_available", false, "This certificate was unpublished by its organiser (tombstone).");
    return { checks, verdict: "failed" };
  }
  if (record.algorithm_version !== "gd-v1" || record.canon_version !== "canon-v1") {
    add("algorithm_supported", false, `This verifier implements gd-v1/canon-v1, record says ${record.algorithm_version}/${record.canon_version}.`);
    return { checks, verdict: "failed" };
  }

  const c = commitment(record);
  add("commitment_matches", c === record.commitment && record.chain_hash === chain.hash, c === record.commitment ? "Recomputed commitment matches." : `Recomputed ${c}.`);

  const committedMs = Date.parse(record.committed_at);
  const R = targetRound(committedMs, chain);
  add("target_round_rule", R === record.target_round, `round_at(committed_at) + 2 = ${R}; record says ${record.target_round}.`);
  const gap = roundTimeMs(record.target_round, chain) - committedMs;
  add("round_published_after_commit", gap > 0, `Round ${record.target_round} was published ${(gap / 1000).toFixed(3)} s after the commitment.`);

  const lh = logHash(record.prev_log_hash, record.commitment, record.log_seq, record.committed_at);
  add("log_hash_matches", lh === record.log_hash, `log entry #${record.log_seq} hash ${lh === record.log_hash ? "matches" : "differs"}.`);
  if (logEntry) {
    const ok =
      logEntry.seq === record.log_seq &&
      logEntry.draw_id === record.draw_id &&
      logEntry.commitment === record.commitment &&
      logEntry.committed_at === record.committed_at &&
      logEntry.log_hash === record.log_hash;
    add("log_entry_published", ok, ok ? `The public log's entry #${record.log_seq} is this commitment.` : "The public log entry differs from the record.");
  }

  if (entries) {
    const ok = entries.entries_hash === record.entries_hash;
    add("entries_hash_matches", ok, ok ? `Your list gives the committed entries hash (${entries.entries.length} entries).` : `Your list gives ${entries.entries.length} entries and hash ${entries.entries_hash}.`);
  }

  if (!record.drand_signature) {
    add("drand_round_published", false, "The draw is still pending its drand round.");
    return { checks, verdict: checks.some((x) => !x.pass && x.name !== "drand_round_published") ? "failed" : "pending" };
  }

  const sig = record.drand_signature.toLowerCase();
  const randomness = hex(sha256(unhex(sig)));
  if (record.drand_randomness) add("drand_randomness_matches", randomness === record.drand_randomness, "drand randomness = SHA-256(signature).");
  const bls = await blsVerify(sig, record.target_round, chain);
  if (bls === null) add("drand_signature_valid", true, "BLS not checked locally (npm i @noble/curves to enable); see relay check.");
  else add("drand_signature_valid", bls, bls ? "BLS signature verifies against the quicknet public key." : "BLS signature does NOT verify.");
  if (relaySignatures) {
    const agree = relaySignatures.filter((r) => r.signature === sig);
    add(
      "drand_relays_agree",
      relaySignatures.length >= 1 && agree.length === relaySignatures.length,
      `${agree.length}/${relaySignatures.length} independent drand relays return the same signature for round ${record.target_round}${relaySignatures.length ? ` (${relaySignatures.map((r) => new URL(r.relay).host).join(", ")})` : ""}.`,
    );
  }

  const sel = select(record.entries_hash, randomness, record.entry_count, record.num_winners, record.num_alternates);
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i].entry_index);
  const ok = same(sel.winners, record.winners) && same(sel.alternates, record.alternates) && (!record.final_randomness || record.final_randomness === sel.final_randomness);
  add("winners_reproduced", ok, ok ? "Winners and alternates recomputed exactly." : "Recomputed winners differ from the record.");

  return { checks, verdict: checks.every((x) => x.pass) ? "verified" : "failed", recomputed: sel };
}

// ---- CLI -----------------------------------------------------------------------------------

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--offline" || k === "--json" || k === "--no-header") a[k.slice(2)] = true;
    else if (k.startsWith("--")) a[k.slice(2)] = argv[++i];
    else a._.push(k);
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const ref = args._[0];
  if (!ref && !args.record) {
    console.log("usage: node verify.mjs <draw-id | certificate-url> [--entries list.txt | --csv list.csv [--column Name] [--no-header]] [--base URL] [--record draw.json] [--offline] [--json]");
    process.exit(2);
  }
  let base = (args.base ?? "https://draw.surveydraw.com.au").replace(/\/+$/, "");
  let id = ref;
  const m = ref && /^(https?:\/\/[^/]+)\/d\/([a-z2-7]{10})/i.exec(ref);
  if (m) {
    if (!args.base) base = m[1];
    id = m[2].toLowerCase();
  }

  const record = args.record ? JSON.parse(await readFile(args.record, "utf8")) : await getJson(`${base}/d/${id}.json`);
  let entries;
  if (args.entries) entries = canonicaliseFile(await readFile(args.entries), { format: "txt", dedupe: record.dedupe });
  if (args.csv) {
    entries = canonicaliseFile(await readFile(args.csv), {
      format: "csv",
      dedupe: record.dedupe,
      column: args.column,
      header: !args["no-header"],
      handleColumn: args["handle-column"],
    });
  }

  let relaySignatures;
  let logEntry;
  if (!args.offline) {
    if (record.drand_signature) relaySignatures = (await fetchRound(record.target_round, RELAYS.slice(0, 2), record.chain_hash ?? QUICKNET.hash)).slice(0, 2);
    try {
      const slice = await getJson(`${base}/api/chain?from=${record.log_seq}&to=${record.log_seq}`);
      logEntry = slice.entries?.[0];
    } catch {
      /* log endpoint unreachable: skip */
    }
  }

  const result = await verifyRecord(record, { entries, relaySignatures, logEntry });
  if (args.json) {
    console.log(JSON.stringify({ draw_id: record.draw_id, ...result }, null, 2));
  } else {
    console.log(`Draw ${record.draw_id}: ${result.verdict.toUpperCase()}`);
    for (const c of result.checks) console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}: ${c.detail}`);
    if (result.recomputed && entries && entries.entries_hash === record.entries_hash) {
      result.recomputed.winners.forEach((i, k) => console.log(`  Winner ${k + 1}: ${JSON.stringify(entries.entries[i])} (entry #${i + 1})`));
      result.recomputed.alternates.forEach((i, k) => console.log(`  Alternate ${k + 1}: ${JSON.stringify(entries.entries[i])} (entry #${i + 1})`));
    }
  }
  process.exit(result.verdict === "verified" ? 0 : result.verdict === "pending" ? 3 : 1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(2);
  });
}
