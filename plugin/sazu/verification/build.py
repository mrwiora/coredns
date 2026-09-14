#!/usr/bin/env python3
"""Builds SAZU-VERIFICATION-DOSSIER.html from the three YAML source
files in data/ -- the Requirements Specification, Test Specification,
and Test Report that together make up the dossier.

Usage:
    .venv/bin/python build.py [--out PATH]

See README.md for the data files' schema and how to add a requirement
or test case. Every count and cross-reference in the rendered document
(requirement totals, area counts, "N passing" stats) is computed here
from the data itself -- never hand-maintained -- specifically because
hand-maintaining those numbers directly in the HTML is what caused
several real mistakes during this dossier's early revisions (see
SAZU-PLAN.md). validate() below additionally catches the two mistakes
most likely to recur even with generation: a test case citing a
requirement ID that doesn't exist, and a requirement no test case
claims to verify.
"""
import argparse
import pathlib
import sys

import jinja2
import yaml

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"


def load(name):
    with open(DATA / name, encoding="utf-8") as f:
        return yaml.safe_load(f)


def all_requirement_ids(req):
    ids = []
    for area in req["areas"]:
        for r in area["requirements"]:
            ids.append(r["id"])
    for n in req["non_functional_requirements"]:
        ids.append(n["id"])
    return ids


def all_verifies_ids(ts):
    """Every requirement ID referenced anywhere in any test case's
    "verifies" field, as a set."""
    import re
    ids = set()
    for area in ts["areas"]:
        for c in area["cases"]:
            for tok in re.split(r"[,\s]+", c["verifies"]):
                tok = tok.strip().rstrip(".")
                if re.match(r"^[A-Z]+-\d+$", tok):
                    ids.add(tok)
    return ids


def validate(req, ts):
    """Cross-checks the two documents against each other, returning
    (problems, notes): problems is a list of human-readable issues that
    should be fixed (empty if none); notes is a list of requirements
    with no test citation that are explicitly, deliberately documented
    as such via requirements.yaml's coverage_exceptions (e.g. verified
    narratively rather than per-test-case, or a genuinely known,
    tracked gap) -- printed for visibility but not treated as a
    problem. This is the whole reason these are structured data and not
    hand-edited HTML: a requirement with no covering test case and no
    acknowledged reason, or a test case citing a requirement that was
    renamed/removed, is now a build-time signal instead of something
    only ever noticed by manually grep-counting."""
    problems = []
    req_ids = all_requirement_ids(req)

    seen = set()
    for rid in req_ids:
        if rid in seen:
            problems.append(f"duplicate requirement id: {rid}")
        seen.add(rid)

    tc_ids = []
    for area in ts["areas"]:
        for c in area["cases"]:
            tc_ids.append(c["id"])
    seen = set()
    for tid in tc_ids:
        if tid in seen:
            problems.append(f"duplicate test case id: {tid}")
        seen.add(tid)

    exceptions = {e["id"]: e["reason"] for e in req.get("coverage_exceptions", [])}
    for eid in exceptions:
        if eid not in set(req_ids):
            problems.append(f"coverage_exceptions names {eid}, which is not a defined requirement id")

    verified = all_verifies_ids(ts)
    req_id_set = set(req_ids)
    notes = []
    for rid in req_id_set:
        if rid not in verified:
            if rid in exceptions:
                notes.append(f"{rid} has no test citation, but is a documented exception: {exceptions[rid]}")
            else:
                problems.append(f"requirement {rid} is not verified by any test case, "
                                 f"and has no coverage_exceptions entry explaining why")
    for vid in verified:
        if vid not in req_id_set:
            problems.append(f"a test case verifies {vid}, which is not a defined requirement id")

    return problems, notes


def lookup(rows, key_field, key, value_field):
    for row in rows:
        if row[key_field] == key:
            return row[value_field]
    raise KeyError(f"no row with {key_field}={key!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "SAZU-VERIFICATION-DOSSIER.html"))
    ap.add_argument("--strict", action="store_true",
                     help="exit non-zero on any validation problem (default: warn only)")
    args = ap.parse_args()

    req = load("requirements.yaml")
    ts = load("test-specification.yaml")
    tr = load("test-report.yaml")

    problems, notes = validate(req, ts)
    for n in notes:
        print(f"NOTE: {n}", file=sys.stderr)
    for p in problems:
        print(f"WARNING: {p}", file=sys.stderr)
    if problems and args.strict:
        print(f"{len(problems)} validation problem(s), aborting (--strict)", file=sys.stderr)
        sys.exit(1)

    total_requirements = len(all_requirement_ids(req))
    total_areas = len(req["areas"])
    total_nfrs = len(req["non_functional_requirements"])

    branch = lookup(tr["execution_summary"]["details"], "item", "Branch", "value")
    commit = lookup(tr["execution_summary"]["details"], "item", "Commit", "value")
    tests_total = lookup(tr["execution_summary"]["stats"], "label", "tests run", "value")
    failures = lookup(tr["execution_summary"]["stats"], "label", "failures", "value")
    tests_passing = tests_total - failures

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(HERE)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=False,
        undefined=jinja2.StrictUndefined,
    )
    template = env.get_template("template.html.j2")
    html = template.render(
        title="SAZU Verification Dossier",
        kicker=f"\U0001f50f SAZU &middot; {branch}",
        lede=("Requirements, test specification, and test execution report for "
              "Self-Authenticated Zone Update &mdash; the split-signing DNSSEC push "
              "mechanism implemented as a CoreDNS plugin, derived directly from the "
              "codebase and its governing RFCs."),
        subject_system=("SAZU on CoreDNS &mdash; <code class=\"inline\">plugin/sazu</code>, "
                         "<code class=\"inline\">plugin/sazu/cmd/*</code>, "
                         "<code class=\"inline\">core/dnsserver</code>, "
                         "<code class=\"inline\">plugin/pkg/doh</code>, "
                         "<code class=\"inline\">plugin/pkg/dnsutil</code>"),
        derivation=("Requirements traced to the SAZU protocol design and its governing RFCs; "
                    "test cases traced to the actual Go test suite; results from a full "
                    "<code class=\"inline\">go test ./...</code> run."),
        branch=branch, commit=commit,
        tests_total=tests_total, tests_passing=tests_passing,
        req=req, ts=ts, tr=tr,
        stats={"total_requirements": total_requirements, "total_areas": total_areas,
               "total_nfrs": total_nfrs},
    )

    out_path = pathlib.Path(args.out)
    out_path.write_text(html, encoding="utf-8")
    print(f"wrote {out_path} ({len(html)} bytes); "
          f"{total_requirements} requirements, {total_areas} areas, {total_nfrs} NFRs, "
          f"{len(problems)} validation warning(s)")


if __name__ == "__main__":
    main()
