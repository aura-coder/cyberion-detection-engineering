import glob, json, os
d = json.load(open("tests/results/effectiveness.json"))
files = sorted(os.path.basename(f) for f in glob.glob("rules/sigma/*.yml"))
base = [f for f in files if f.startswith("base_")]
corr = [f for f in files if f.startswith("correlation_")]
stand = [f for f in files if f not in base and f not in corr]
tested = [f for f in stand if d.get(f, 0) > 0]
untested = [f for f in stand if f not in tested]
print(f"{'Standalone rule':<52s} {'Matches':>8s}")
print("-" * 62)
for f in stand:
    print(f"{f:<52s} {d.get(f, 0):>8d}   {'OK' if f in tested else 'UNTESTED'}")
print()
print(f"Standalone detection rules : {len(stand)}")
print(f"  tested, matched real data: {len(tested)}  ({len(tested)/max(len(stand),1)*100:.0f}%)")
print(f"  untested / no match      : {len(untested)}")
print(f"Base building blocks       : {len(base)}  (not counted - they match whole event types)")
try:
    cr = json.load(open("tests/results/correlation_real.json"))
    print(f"Correlation rules          : {len(corr)}  (real-corpus hits: " + ", ".join(f"{k[:40]}={v.get('hits', 'n/a')}" for k, v in cr.items()) + ")")
except FileNotFoundError:
    print(f"Correlation rules          : {len(corr)}  (run scripts/run_effectiveness.py first)")
