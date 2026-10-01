# giveaway-verify

Check a Giveaway Draw certificate yourself, without trusting the people who ran it.

This repository holds:

- **`verify.mjs`**: a single-file verifier for Node.js 20+. It is a separate implementation of the
  published spec ([gd-v1](https://draw.surveydraw.com.au/spec/gd-v1), [canon-v1](https://draw.surveydraw.com.au/spec/canon-v1)),
  not a copy of the server's code.
- **`anchors/`**: an hourly record of the public commitment log's head, committed by a GitHub Action.
  GitHub's history is an independent witness: if anyone rewrote old commitments, the log's later
  hashes would stop matching what was recorded here.

## Verify a draw

You need the certificate link (or draw ID) and, to check the entries, the list that was drawn
(ask the organiser for it).

```bash
curl -sO https://draw.surveydraw.com.au/verify.mjs      # or clone this repo
node verify.mjs https://draw.surveydraw.com.au/d/k7q2m3x4tp --entries entries.txt
```

For a CSV file:

```bash
node verify.mjs k7q2m3x4tp --csv entries.csv --column "Name"            # header row assumed
node verify.mjs k7q2m3x4tp --csv entries.csv --column 2 --no-header
```

Example output:

```
Draw k7q2m3x4tp: VERIFIED
  PASS  commitment_matches: Recomputed commitment matches.
  PASS  target_round_rule: round_at(committed_at) + 2 = 32696691; record says 32696691.
  PASS  round_published_after_commit: Round 32696691 was published 4.215 s after the commitment.
  PASS  log_hash_matches: log entry #12 hash matches.
  PASS  log_entry_published: The public log's entry #12 is this commitment.
  PASS  entries_hash_matches: Your list gives the committed entries hash (22 entries).
  PASS  drand_randomness_matches: drand randomness = SHA-256(signature).
  PASS  drand_signature_valid: BLS signature verifies against the quicknet public key.
  PASS  drand_relays_agree: 2/2 independent drand relays return the same signature for round 32696691 (api.drand.sh, drand.cloudflare.com).
  PASS  winners_reproduced: Winners and alternates recomputed exactly.
  Winner 1: "Ngaio Parata" (entry #7)
```

Exit codes: `0` verified, `1` a check failed, `3` the draw is still waiting for its drand round, `2` usage or network error.

Options: `--base URL` (another deployment), `--record draw.json` (use a saved copy of `/d/{id}.json`),
`--offline` (no network: skips the relay and public-log checks), `--json` (machine-readable output).

### BLS signature check

`verify.mjs` has no dependencies. With no dependencies it checks the drand signature by asking two
independent drand relays for the same round and comparing. To also check the BLS signature against
the pinned quicknet public key locally, install the optional dependency first:

```bash
npm install          # installs @noble/curves (optional dependency)
```

## What each check means

| Check | What it shows |
|---|---|
| `commitment_matches` | The certificate's settings (entries hash, number of entries, dedupe mode, winners, alternates, drand round, commit time) are exactly what was committed. None of them can be changed afterwards. |
| `target_round_rule` | The drand round was fixed by rule from the commit time (`round_at(committed_at) + 2`), not chosen. |
| `round_published_after_commit` | That round did not exist yet when the draw was committed, so nobody could know the randomness in advance. |
| `log_hash_matches` / `log_entry_published` | The commitment is in the public, append-only log at the stated position. |
| `entries_hash_matches` | Your list is the list that was drawn (after the published clean-up rules). |
| `drand_signature_valid` / `drand_relays_agree` | The randomness is genuine drand quicknet output. |
| `winners_reproduced` | The winners follow exactly from the list and the randomness under gd-v1. |

What it does **not** show: that the list was complete, or that every entrant was eligible. That is
the organiser's responsibility. Only re-draws of the exact same list are counted on a certificate.

## Run the tests

```bash
node test.mjs     # golden vectors for gd-v1 / canon-v1
```

## The anchor Action

`.github/workflows/anchor.yml` runs hourly. It fetches `/api/chain/head`, checks the new head
extends the last anchored head (re-linking every entry in between), then appends the head's JSON
line to `anchors/YYYY/MM/DD.jsonl` and updates `anchors/latest.json`.

- If the API is unreachable, the run is skipped with a notice. Nothing is committed and nothing fails.
- If the history changed (a head with the same number but a different hash, a head that went
  backwards, or a chain that doesn't link), the run records it in `anchors/ALERTS.jsonl` and fails.

To point it at a different deployment, set the repository variable `ANCHOR_SOURCE_URL` to the full
`/api/chain/head` URL.

## Licence

MIT. See [LICENSE](LICENSE).
