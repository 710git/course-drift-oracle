# Why chain.v2.jsonl is an archive, not the live chain

`chain.v2.jsonl` holds the 64 receipts this oracle published between
2026-08-28T02:39:45Z and 2026-08-31T17:07:03Z, sequences 0 through 63,
all signed by public key `C-FzD6a8QDShF2oejGoZ25GKrt-F17CKgnMbklSz-R0`.
The archive verifies end to end: every signature valid, every link
correct. You can check it yourself with
`python verify_chain.py --chain chain.v2.jsonl` and no code from us.

Nothing was wrong with those receipts. The signing key behind them was
held in a secret store with no offline backup, and a trust root that
exists in exactly one unreadable place is a liability that only grows
once receipts are in buyers' hands. With zero external buyers this was
the last cheap moment to fix that, so the identity was retired
deliberately rather than risked.

What holds, and what changes:

- Every receipt in this archive remains independently verifiable
  forever. Verification needs only the receipt itself; the public key
  travels inside it.
- The live chain (`chain.jsonl`) starts fresh at sequence 0 under a new
  key whose seed was backed up offline before it ever signed anything.
  The new public key appears in every receipt the deployed worker
  serves; fetch the free `drift_summary` tool and read it from there.
- `chain.v1.jsonl` records an earlier reset, before launch, for the
  same class of reason. The pattern is intentional: a chain whose key
  custody cannot be stood behind is archived honestly instead of
  continued quietly.

Two safeguards were added while performing this reset, both visible in
this repository:

1. `publish.py` refuses to start a fresh chain when an archived chain
   beside it is signed by the key currently in use, so a reset that
   forgot to rotate the key fails loudly instead of silently restarting
   the sequence under the retired identity.
2. `sign_skill.py` re-signs the published skill receipt when the
   signing identity changes. Its idempotence check previously asked
   only whether the existing receipt verified, and a receipt signed by
   a retired key still verifies, so a rotation would have left the
   skill advertising the old identity.
