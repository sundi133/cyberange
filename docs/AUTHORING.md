# Authoring scenarios

A scenario is a curated selection of modules plus a story — objectives, mode,
difficulty. The catalog ships 10, but a scenario is cheap to make because the
hard content (the modules) already exists: authoring is composition, not new
attack content. This is how a catalog grows from 10 to 100.

## The config format

Write a compact config (YAML or JSON) and the builder turns it into a full,
validated scenario. The minimum is a name, a mode, and the modules to run:

```yaml
name: Linux web-to-root
mode: red-blue              # red-blue | solo | purple
difficulty: intermediate    # introductory | intermediate | advanced
modules:
  - CR-MOD-WEBAPP-001
  - CR-MOD-EXEC-LNX-001
  - CR-MOD-PRIVESC-LNX-001
```

Everything else is derived or defaulted:

| Field | Default |
|---|---|
| `id` | generated from the name (`CR-CUSTOM-…`), made unique |
| `technique_ids` | the union of the modules' techniques |
| `topology_id` | `TOPO-DOCKER` if any module is docker, else `TOPO-STD5` |
| `safety_class` | the highest (most restrictive) of the modules' |
| `duration_min` | `[60, 90]` |
| `objectives` | a sensible pair for the mode (red/blue, or solo, or purple) |

Override any of them by adding the field. A file may hold one config (a mapping)
or several (a list). See `examples/scenario-configs/` for working examples.

## Building

```bash
python3 scripts/build_scenarios.py examples/scenario-configs/   # a directory
python3 scripts/build_scenarios.py my-scenario.yaml             # one file
python3 scripts/build_scenarios.py configs/ --merge             # add to existing
```

Output goes to `backend/cyberrange/seed/scenarios.staged.json`, which the
catalog loads alongside the curated seed. Built scenarios show in the catalog
marked **✎ Custom** and are launchable on the next server start. YAML configs
need PyYAML (a venv — see [IMPORTING.md](IMPORTING.md)); JSON configs need
nothing.

## The safety boundary

Validation is strict and it is the point: **every module a scenario references
must exist and be signed.** A scenario cannot be built on unsigned or imported
content. So a customer can author scenarios freely — and compose only modules a
reviewer already trusted. A scenario is safe by construction, which is why it
needs no separate signing of its own.

The builder rejects, with a message, any config that: has no name, uses an
invalid mode or difficulty, lists no modules, or references an unknown or
unsigned module.

## Letting customers author

This config format is the customer authoring path today: hand them the format,
they write configs, you (or they) run the builder. Because the builder refuses
unsigned modules, a customer cannot author their way around module review.

An in-product "Create scenario" form — pick modules, set objectives, save, no
files — is the planned next step (path B), built on this same validation layer.
See the TODO in [../deploy/vm/README.md](../deploy/vm/README.md) is for the VM
tier; scenario-authoring TODOs live here:

- [ ] In-product scenario authoring: an API (`POST /api/scenarios`) and an
      instructor/admin UI form that composes a scenario from the module picker
      and runs it through the same validation this builder uses.
- [ ] Optional `learning` block in configs (briefing, concepts, quiz), so
      authored scenarios can be assigned as guided lessons, not just launched.
