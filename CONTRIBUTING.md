# Contributing

Contributions are welcome: new rules, parser coverage, report improvements,
tests and documentation.

## Development setup

```console
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

The runtime dependency is PyYAML. Development tools are pytest, pytest-cov,
ruff and bandit.

## Before opening a pull request

Run the full gate:

```console
make check
```

That is equivalent to:

```console
ruff check .
ruff format --check .
bandit -r src
pytest
```

A change is ready when all four pass. If you touched a parser or the engine,
add a test that fails before the change and passes after it. If you touched the
CLI, exercise the relevant exit-code path as well as the happy path.

## Adding a detection rule

1. Copy the shape of an existing file in `src/argus/rules/`.
2. Use the next free `ARGUS-####` identifier and a descriptive file name.
3. Include a description of at least 20 characters, a severity, a logsource,
   at least one ATT&CK technique tag and at least one realistic false positive.
4. Run `argus rules validate` and `argus rules lint`.
5. Run the rule against `examples/logs/benign`. It must not add a
   medium-or-higher alert.
6. Add a case to `examples/logs/attack/` only when it supports a coherent
   scenario, not just to make one rule fire. Keep the corpus readable.
7. Add a focused test for any new matcher or correlation feature the rule uses.

Rule authors should read [docs/WRITING_RULES.md](docs/WRITING_RULES.md).

## Parser changes

A parser must:

- return `None` for a line it cannot interpret, so the stream can count it as
  malformed rather than aborting the scan,
- normalise timestamps to timezone-aware UTC,
- populate `action` with a stable list of strings,
- preserve useful raw fields for evidence and rule matching,
- never read more than one line at a time beyond the bounded sample used for
  auto-detection.

Add fixtures for both the accepted format and the malformed cases. Do not make
an existing fixture pass by loosening a regular expression beyond what the real
format allows.

## Reports

The console report is for people, JSON-lines is for pipelines, and Markdown and
HTML are for review and archival. Keep the formats consistent:

- JSON-lines emits one alert object per line and no metadata record.
- Markdown and HTML include scan metadata and ATT&CK coverage.
- Every value derived from a log line is escaped for its output context.
- The HTML report stays standalone: no CDN, fonts, images or scripts fetched
  at runtime.

## Style

- Python 3.10 compatibility. Do not use syntax that requires a newer version.
- Keep functions small and explicit. Prefer a clear guard clause over a deeply
  nested branch.
- Use the existing naming and dataclass patterns.
- Do not add a runtime dependency without a strong reason and a discussion in
  the pull request.
- Do not commit generated reports, virtual environments, caches or build
  artifacts.

## Tests

The suite uses small deterministic fixtures. Prefer constructing an `Event`
directly when testing the engine, and use a real parser when testing a log
format. Avoid sleeping, network access and dependence on the wall clock. The
corpus under `examples/logs/` is part of the regression surface; changes to it
should be reflected in `examples/scenario-breach.md` and in the expected counts.

## Documentation

Update the relevant document when behaviour changes:

- `README.md` for installation, commands and exit codes,
- `docs/WRITING_RULES.md` for the rule schema or condition grammar,
- `docs/DETECTIONS.md` for the rule index and coverage,
- `examples/scenario-breach.md` for the corpus timeline,
- `CHANGELOG.md` for user-visible changes.

Show real command output. If an example is abbreviated, say so and show the
command that produces the full result.

## Licence

By contributing, you agree that your contribution is licensed under the MIT
licence used by this project.
