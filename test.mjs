// node test.mjs: checks verify.mjs against the published golden vectors (gd-v1 / canon-v1).
import { readFileSync } from "node:fs";
import { canonicaliseFile, canonicaliseList, commitment, QUICKNET, select, targetRound } from "./verify.mjs";

const { vectors } = JSON.parse(readFileSync(new URL("./vectors/gd-v1.json", import.meta.url), "utf8"));
let failed = 0;
const eq = (name, a, b) => {
  const ok = JSON.stringify(a) === JSON.stringify(b);
  if (!ok) {
    failed++;
    console.log(`  FAIL ${name}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`);
  }
};

for (const v of vectors) {
  const c = canonicaliseList(v.entries, v.dedupe);
  const R = targetRound(Date.parse(v.committed_at));
  const sel = select(c.entries_hash, v.drand_randomness, c.entries.length, v.num_winners, v.num_alternates);
  eq(`${v.name}: canonical file`, c.file, v.expected.canonical_file);
  eq(`${v.name}: entries hash`, c.entries_hash, v.expected.entries_hash);
  eq(`${v.name}: same hash via a CRLF .txt file`, canonicaliseFile(new TextEncoder().encode(v.entries.join("\r\n")), { format: "txt", dedupe: v.dedupe }).entries_hash, v.expected.entries_hash);
  eq(`${v.name}: target round`, R, v.expected.target_round);
  eq(
    `${v.name}: commitment`,
    commitment({ draw_id: v.draw_id, entries_hash: c.entries_hash, entry_count: c.entries.length, dedupe: v.dedupe, num_winners: v.num_winners, num_alternates: v.num_alternates, chain_hash: QUICKNET.hash, target_round: R, committed_at: v.committed_at }),
    v.expected.commitment,
  );
  eq(`${v.name}: final randomness`, sel.final_randomness, v.expected.final_randomness);
  eq(`${v.name}: winners`, sel.winners, v.expected.winners);
  eq(`${v.name}: alternates`, sel.alternates, v.expected.alternates);
  console.log(`${failed ? "…" : "ok"}  ${v.name}`);
}
console.log(failed ? `${failed} check(s) failed` : `all ${vectors.length} vectors pass`);
process.exit(failed ? 1 : 0);
