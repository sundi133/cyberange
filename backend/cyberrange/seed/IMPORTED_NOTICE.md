# Imported content attribution

`modules.imported.json` contains CyberRange behavior modules converted from
**Atomic Red Team** (https://github.com/redcanaryco/atomic-red-team), which is
licensed under the **MIT License**, Copyright (c) Red Canary.

Only the benign Linux-shell subset (no download / destructive / credential /
persistence / privilege-escalation indicators, no elevation required) was
reviewed and signed as safety class **S1**. Each module records its provenance
under its `_import` key and its review under `_review`. Modules execute only in
the platform's isolated container tier (`--network none`, resource-capped, no
host mounts, auto-removed).

The broader import (Windows / macOS / cloud atomics, and flagged Linux tests)
is intentionally left unsigned for human review — run `python -m cyberrange
import-atomics` against an Atomic Red Team checkout to stage it locally.
