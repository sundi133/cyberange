# Scenario config examples

Compact configs the scenario builder turns into full catalog scenarios. One
file can hold a single config (a mapping) or several (a list). YAML and JSON
both work; JSON needs no dependency.

Build them:

```bash
python3 scripts/build_scenarios.py examples/scenario-configs/
```

See the header of `scripts/build_scenarios.py` for the full field list. The
only hard rules: a `name`, a valid `mode` (red-blue / solo / purple), and at
least one `module` — and every module must exist and be **signed** (a scenario
cannot be built on unreviewed imported content).
