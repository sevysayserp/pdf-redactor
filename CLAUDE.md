# CLAUDE.md — standing rules for this repo

## Privacy guardrails (non-negotiable)

1. This tool exists so that real documents never have to be shown to an AI
   assistant or any other third party. Real documents and any real
   `redaction_list.txt` live OUTSIDE this repository. NEVER read, list, or
   extract text from a location the user identifies as holding real
   documents, and never copy or symlink real documents into the repo.
2. Use `testdata/` (fabricated documents) for all development and
   debugging. Do not "peek" at real files to debug a redaction miss — ask
   the user for the `--audit` output (categories + line numbers only) or a
   made-up reproduction.
3. NEVER output, log, or commit an SSN, EIN, account number, date of birth,
   or home address — not even in error messages or test output. Use the
   fake values from `testdata/` in examples.
4. `redaction_list.txt` is sensitive wherever it lives (the fake one in
   `testdata/` is the only exception). Do not read a real one; the script
   consumes it directly. The same goes for the master list
   (`~/.config/pdf-redactor/master_redaction_list.txt` or any `--master`
   path): never read or list it, and run the script with `--no-master` (or
   a fake `--master` file) during development so its values never reach
   preview output. The test suite isolates itself via `tests/conftest.py`.
5. `--audit` and the post-run self-check print categories + line numbers
   only, never matched text, so their output is safe to read and share.
   Keep it that way: never add matched values to that output. The same
   holds for `--inspect` (counts and sizes only, no text, no file names).

## Project conventions

6. Python 3.10+, dependencies in requirements.txt, venv at venv/
   (gitignored, no leading dot). Create it with
   `python3 -m venv --prompt pdf-redactor venv` so the activated shell
   shows the project name.
7. Run `pytest` before every commit.
8. Plan-mode first for any change touching redact.py's pattern list — the
   user reviews redaction-logic changes before they're applied.
9. This repository is public. Nothing in it may reference the user's real
   institutions, locations, or documents; examples use `testdata/` values.
