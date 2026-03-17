# canopy/web-crypto — TODO

## Status: Implementation Complete, Tests Critically Low (v1.0.0)

~100+ functions across 6 modules covering hashing, HMAC, encryption, signing, key management. But only 2 tests.

---

## Critical: Test Coverage

- [ ] **Only 2 tests for ~100+ functions** — this is unacceptable for a security-critical package
- [ ] Add tests for `Crypto.Hash`: all 4 algorithms (SHA-1, SHA-256, SHA-384, SHA-512), digest vs digestHex vs digestString
- [ ] Add tests for `Crypto.Hmac`: key generation, import/export, sign/verify roundtrips
- [ ] Add tests for `Crypto.Encrypt`: AES-GCM, AES-CBC, AES-CTR encrypt/decrypt roundtrips, password-based encryption
- [ ] Add tests for `Crypto.Sign`: ECDSA and RSA sign/verify roundtrips, all curve types
- [ ] Add tests for `Crypto.Key`: all import/export formats, key derivation (PBKDF2, HKDF)
- [ ] Add tests for `Crypto`: randomBytes, randomUUID, isAvailable, error types
- [ ] Add tests for all toString/fromString conversion functions
- [ ] Add tests for configuration record construction

---

## Features to Add

- [ ] Streaming encryption/decryption (for large files)
- [ ] Key wrapping/unwrapping (wrapKey, unwrapKey)
- [ ] X25519 key exchange (when browser support lands)
- [ ] Ed25519 signing (when browser support lands)
- [ ] Secure key storage recommendations/patterns
- [ ] `Crypto.Password` — High-level password hashing API

---

## Code Quality

- [ ] Add type annotations to all functions
- [ ] Add comprehensive Haddock documentation (security-critical code needs excellent docs)
