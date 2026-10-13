# Technical decisions

- **Local-first, dependency-free runtime.** Only Node.js built-ins are used by the scanning engine. Installing build dependencies still requires network access.
- **Conservative detection.** No request is sent to a credential provider to check validity; a high finding means a plausible secret shape, not a verified active key.
- **Git index reading.** Staged scans read blobs from the index (rather than the mutable working tree), inspect file size before contents, and fail closed on skipped eligible large/binary files.
- **Tracked .env files.** These are reported even if unchanged during a staged scan.
- **No automatic secret modifications.** The CLI reports recovery steps. Future fix commands must require explicit review before changing code.
- **Path privacy.** Match values are not printed. Known token formats are redacted if they appear in a path. Arbitrary filenames may remain sensitive.
- **Contributors.** Add positive and negative regression tests for any rule. Prefer few explainable detections over a large noisy ruleset.
