import csv
rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
cov = sum(1 for r in rows if r["Status"] == "Covered")
par = sum(1 for r in rows if "Partially" in r["Status"])
nco = sum(1 for r in rows if r["Status"] == "Not Covered")
print(f"Total:  {len(rows)}")
print(f"  Covered:            {cov}")
print(f"  Partially Covered:  {par}")
print(f"  Not Covered:        {nco}")
print()
print(f"{'Tactic':<22s} {'Technique':<12s} {'Name':<38s} {'Status'}")
print("-" * 90)
for r in rows:
    print(f"{r['Tactic']:<22s} {r['Technique ID']:<12s} {r['Technique Name'][:36]:<38s} {r['Status']}")
