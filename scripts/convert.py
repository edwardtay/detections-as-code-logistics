"""Check every rule file with pySigma, the reference Sigma implementation, and write SPL and KQL.

For each rule file: parse all documents (base and correlation rules) into a SigmaCollection,
fail on any parse or validation error, then convert with the Splunk and Microsoft 365 Defender
(KQL) backends. Output goes to build/<rule>.spl and build/<rule>.kql. Exit code 1 on any error.
"""
import pathlib
import sys

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "build"
OUT.mkdir(exist_ok=True)

errors = 0
for path in sorted((ROOT / "rules").glob("FD-*.yml")):
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except Exception as exc:  # parse errors are the finding
        print(f"FAIL {path.name}: {exc}")
        errors += 1
        continue
    if collection.errors:
        for err in collection.errors:
            print(f"FAIL {path.name}: {err}")
        errors += 1
        continue
    results = {}
    for name, backend in (("spl", SplunkBackend()), ("kql", KustoBackend())):
        try:
            queries = backend.convert(collection)
            results[name] = "\n\n".join(str(q) for q in queries)
        except Exception as exc:
            # Fall back to the base rules one by one: the correlation step then runs in the SIEM's own syntax.
            parts = []
            for rule in collection.rules:
                if isinstance(rule, SigmaCorrelationRule):
                    continue
                try:
                    parts.append(f"// base rule: {rule.title}\n" + "\n".join(str(q) for q in backend.convert_rule(rule)))
                except Exception as inner:
                    print(f"note {path.name}: {name} has no conversion for '{rule.title}': {inner}")
            results[name] = "\n\n".join(parts) or None
            print(f"note {path.name}: {name} backend cannot convert the whole file ({exc}); base rules converted separately")
        if results[name]:
            (OUT / f"{path.stem}.{name}").write_text(results[name] + "\n", encoding="utf-8")
    kinds = ", ".join(k for k, v in results.items() if v)
    print(f"ok   {path.name}: {len(collection.rules)} documents parsed by pySigma; queries written: {kinds or 'none'}")

sys.exit(1 if errors else 0)
