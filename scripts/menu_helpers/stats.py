from pathlib import Path
import subprocess
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
print(f"Sigma rules:        {sh('ls rules/sigma/*.yml 2>/dev/null | wc -l')}")
print(f"Correlation rules:  {sh('grep -l \"^correlation:\" rules/sigma/*.yml 2>/dev/null | wc -l')}")
print(f"Base rules:         {sh('ls rules/sigma/base_*.yml 2>/dev/null | wc -l')}")
print(f"Converted queries:  {sh('ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l')}")
print(f"Coverage rows:      {sh('tail -n +2 coverage/attack_coverage.csv | wc -l')}")
print(f"Threat hunts:       {sh('ls hunts/*.md 2>/dev/null | grep -v template | wc -l')}")
print(f"Incident reports:   {sh('ls incidents/*.md 2>/dev/null | grep -v template | wc -l')}")
print(f"IR playbooks:       {sh('ls playbooks/*.md 2>/dev/null | grep -v template | wc -l')}")
print(f"Git-tracked files:  {sh('git ls-files | wc -l')}")
print(f"Git commits:        {sh('git rev-list --count HEAD')}")
