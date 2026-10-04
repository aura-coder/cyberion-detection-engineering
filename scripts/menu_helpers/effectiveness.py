import json
from pathlib import Path
d = json.loads(Path("tests/results/effectiveness.json").read_text())
m = sum(1 for v in d.values() if v > 0); t = len(d)
print(f"{'Rule':<56s} {'Matches':>8s}")
print("-" * 66)
for k, v in d.items():
    mark = "OK" if v > 0 else "no match"
    print(f"{k:<56s} {v:>4d}   {mark}")
print()
print(f"Rules tested:  {t}")
print(f"Rules matched: {m}")
print(f"Success rate:  {m/t*100:.1f}%")
