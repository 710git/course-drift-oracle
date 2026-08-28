# Why chain.v1.jsonl is an archive, not the live chain

`chain.v1.jsonl` holds a single report this service signed during its
pre-launch build (sequence 0, public key
`kTli76HJdp7QCYOTBUT4LTotYYdW28jErmasCHmVapM`). It was never sold: no
buyer paid for it, and no buyer had pinned this key at all.

The Ed25519 private key behind that signature was generated inside a
temporary build environment and was lost when that environment was torn
down, before launch. A chain whose signing key no longer exists cannot be
honestly continued: any new entry would be signed by a different identity
while claiming the same lineage as the old one.

Because this happened before launch - one unsold report, zero buyers,
nothing yet deployed, no key pinned anywhere - the fix is a clean,
disclosed identity reset rather than a silent fork:

- This file and `chain.v1.jsonl` stay in the repository as the record of
  the reset, rather than being deleted or hidden.
- The live chain (`chain.jsonl`) starts fresh at sequence 0 under a new
  key. Every report this service has actually sold was signed under that
  new key, and it is the only key any buyer should trust or pin.
- The new public key appears in every receipt the live service serves,
  so a buyer verifying a report today is verifying against the one key
  that has ever been used to sell anything.

The private key has never, at any point, been committed to a repository -
this one, the mirror, or anywhere else. It lives only in the deploy
system's encrypted secret storage. That is the standing rule this incident
exists to make concrete: a signing key is the trust root of everything a
buyer relies on, and it belongs in a secret store from the moment it signs
anything anyone might rely on, with no exceptions for "just during
development."
