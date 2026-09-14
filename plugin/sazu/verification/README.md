# SAZU Verification Dossier — build pipeline

`SAZU-VERIFICATION-DOSSIER.html` — the Requirements Specification, Test
Specification, and Test Report, as one self-contained page — is
**generated**, not hand-edited. Its three sources live in `data/` as
YAML; `build.py` renders them through `template.html.j2` into the final
HTML.

This replaces an earlier version of this dossier that was one large,
hand-maintained HTML file. That approach broke down in a specific way
worth remembering: every count in the document (how many requirements,
how many test cases, which ones are in each area) had to be
hand-tallied and kept in sync by eye, across three documents, every
time something changed. It didn't just risk becoming wrong — it *did*,
more than once, in ways nobody caught until this rewrite: a leftover
duplicate test-case ID from an earlier revision, a requirement whose
own supporting test had quietly stopped being cited, wording that
drifted out of sync with a later change elsewhere in the same document.
None of that is a hypothetical risk this design avoids -- it's what
this design was built *because of*, after finding it.

## Why YAML + Jinja2 + a venv, not a Go tool

This is the one part of the SAZU codebase that isn't Go, on purpose:
generating a styled, cross-referenced HTML document from structured
data is a much shorter, clearer program in Python with a real
templating engine than the equivalent would be in Go with only the
standard library's `html/template` and `gopkg.in/yaml.v3`-equivalent —
and this dossier is documentation tooling, not something that ships
inside the `coredns` binary, so it doesn't need to be Go for
consistency's sake the way the plugin itself does.

PyYAML and Jinja2 aren't vendored or globally installed — they live in
a local virtualenv (`.venv/`, gitignored) so this stays completely
isolated from anything else on the machine running it:

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Building

```
.venv/bin/python build.py
```

writes `SAZU-VERIFICATION-DOSSIER.html` in this directory. Pass
`--out PATH` to write somewhere else, or `--strict` to exit non-zero if
validation finds a real problem (see below) — useful in a pre-commit
hook or CI step, if this ever gets one.

## The data files

- `data/requirements.yaml` — the Requirements Specification: normative
  references, system overview, one entry per functional area (each
  with its own list of requirements), non-functional requirements, and
  `coverage_exceptions` (see below).
- `data/test-specification.yaml` — the Test Specification: test
  strategy, environment, one entry per area (mirroring the requirements
  areas, plus a standalone `nfr` area) with its test cases, the
  automated suite inventory, and the manual/real-binary verification
  list.
- `data/test-report.yaml` — the Test Report: execution summary,
  results by package and by requirement area, skipped tests, the
  manual verification log, defects found and resolved, and the
  conclusion/sign-off. `execution_summary.details` is where `build.py`
  reads the branch and commit it stamps into the masthead, coversheet,
  and footer, and `execution_summary.stats` is where it reads the
  passing-test count — there is deliberately no separate place these
  are configured, so there is only ever one thing to update.

### Adding a requirement

Add an entry under the right area in `requirements.yaml`:

```yaml
- id: KEY-12
  text: |-
    Some new SHALL statement, word-wrapped at whatever width is
    comfortable -- build.py joins the lines back together with spaces,
    so wrapping is purely for readability here and changes nothing
    about the rendered text.
  source: Engineering decision
```

Then cite it from at least one test case's `verifies` field in
`test-specification.yaml` (see below) — `build.py` will refuse to build
cleanly (warns by default, fails under `--strict`) if it isn't, unless
you also add it to `coverage_exceptions` with a reason (see below).

### Adding a test case

Add an entry under the matching area in `test-specification.yaml`:

```yaml
- id: TC-KEY-20
  objective: |-
    What this test case actually proves, in one or two sentences.
  functions: TestSomeRealGoFunctionName
  verifies: KEY-12
```

`functions` should name real, file-locatable Go test function(s) —
this document exists to be checked against the actual test suite, not
to describe tests that don't exist.

### Text fields and inline HTML

Any field that's long or contains a tag is written as a YAML block
literal (`|-`) and may contain a **small, fixed set** of inline HTML —
`<code class="inline">`, `<em>`, `<strong>`, entities like `&middot;`
and `&sect;` — exactly as it will appear in the rendered page. This is
a deliberate simplification: these documents have always been authored
this way (the tables *are* the content, not a description of it to be
translated), and inventing a Markdown-like layer on top would add a
translation step with its own failure modes for very little benefit.
Treat these fields as trusted HTML fragments, the same way the
plugin's own Go source treats a hand-written `fmt.Sprintf` HTML string
— because that's exactly what they used to be, before this migration.

### `coverage_exceptions`

A requirement with no test case citing it in the whole Test
Specification is a build warning by default (`WARNING:` on stderr,
document still builds) or a hard failure under `--strict`. Some
requirements are legitimately not verified by one specific, named test
case — a non-functional requirement verified by "the whole suite
passing" rather than one test, say — and some are genuine, currently
real gaps that are more useful tracked openly than hidden. Both go in
`requirements.yaml`'s `coverage_exceptions` list:

```yaml
coverage_exceptions:
- id: SOME-REQ-01
  reason: |-
    Known gap: no automated test exercises this path yet. Not
    fabricated coverage -- an honest note that this is still open.
```

An exception downgrades the missing-citation warning to a `NOTE:` line
`build.py` still prints (so it stays visible) without blocking the
build. **Never add an exception just to silence a warning** — if a
requirement has no test and no real reason it can't, the right fix is
to write the test, not to add an exception explaining why one isn't
needed. `coverage_exceptions` is empty as of this writing: this
migration's first run found six requirements with no citation at
all — four legitimately verified by the whole suite passing rather
than one dedicated test (`NFR-01`, `NFR-03`, `NFR-04`, `NFR-05`), and
two genuine gaps (`AUTH-04`, `CARRIER-06`). All six were eventually
resolved the honest way: the four legitimate ones by finding (or, for
`NFR-01`, writing) one concrete existing test case worth citing even
though the property is really about the whole suite passing, and the
two genuine gaps by writing the missing test and citing it for real —
never by leaving an exception in place past the point where a real
citation was possible.

### What the validator checks

`build.py`'s `validate()` catches, every time it runs:

- a requirement ID with no test case citing it (unless listed in
  `coverage_exceptions`);
- a test case whose `verifies` field cites a requirement ID that
  doesn't exist (a typo, or a requirement that was renamed/removed
  without updating the citation);
- a duplicate requirement or test-case ID (how the
  `TC-KEY-07` duplicate mentioned above was actually found).

It does **not** (yet) check that a named Go test function actually
exists in the repository, or that a `functions` field's names are
spelled correctly against the real source tree — that would need this
script to walk the Go source, which is a reasonable future improvement
if this drifts again, but is out of scope for what this migration set
out to fix.

## `template.html.j2`

The shared page shell — fonts, CSS, masthead, coversheet, tab
navigation, and the per-document layout — plus the Jinja2 loops that
turn each YAML document's data into the actual section HTML. Structural
sections (which top-level sections exist, in what order, e.g. "1
Introduction, 2 System overview, 3 Requirements...") are fixed in the
template, since they don't change from one revision to the next; only
the *contents* of each section come from the data files.

## Publishing

The generated HTML is also published as a Claude Code artifact for easy
sharing. After rebuilding, republish it to the same URL rather than
creating a new one — ask whoever last did this for the link, or check
the artifact list.
