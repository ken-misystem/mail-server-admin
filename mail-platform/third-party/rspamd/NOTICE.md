# Rspamd symbols.cache backport

The modified source file `src/libserver/symcache/symcache_impl.cxx` is
Copyright 2025 Vsevolod Stakhov, licensed under Apache-2.0.
The persistence test header also retains its upstream Apache-2.0 notice.
`LICENSE-APACHE-2.0.md` is copied verbatim from Rspamd 3.12.1.
`COPYRIGHT.debian` is copied verbatim from Debian's 3.12.1-1 source package;
it lists the different licenses of bundled dependencies, including LGPL.
These third-party materials are not relicensed under this repository's MIT license.

Upstream fix: [PR 6331](https://github.com/rspamd/rspamd/pull/6331),
commit [381fafc48f4d1c6a3550cb4b5123b78c104513a1](https://github.com/rspamd/rspamd/commit/381fafc48f4d1c6a3550cb4b5123b78c104513a1).

Changes by MI-SYSTEM, 2026-11-16:

- Backport `symcache::save_items()` persistence changes to Debian 3.12.1-1.
- Preserve the original 3.12.1 statistics rounding; do not include unrelated changes.
- Adapt three expectations in the upstream persistence tests to that unchanged rounding.
- Add a pinned source preparation helper and build instructions.

`prepare.py`, the preparation-helper tests, and these instructions are independent
MIT-licensed MI-SYSTEM code/documentation. The C++ patch and C++ tests retain Apache-2.0.
The source archives are obtained from Debian using `source-lock.json`; they are
not embedded here. No runtime binary, private configuration, credentials or operational
logs are distributed by this source-only change. If distributing a built package,
retain all dependency notices and provide the exact corresponding sources, patches
and build instructions required by those components' licenses.
