import csv
import json
from pathlib import Path

csv_path = Path('coverage/attack_coverage.csv')
out_path = Path('coverage/attack_coverage_layer.json')

techniques = []

with csv_path.open() as f:
    reader = csv.DictReader(f)
    for row in reader:
        tid = row['Technique ID']
        status = row['Status']
        color = {
            'Covered': '#00ff00',
            'Partially Covered': '#ffff00',
            'Not Covered': '#ff0000'
        }.get(status, '#cccccc')
        techniques.append({
            'techniqueID': tid,
            'color': color,
            'comment': f"{status}: {row.get('Supporting Rule ID','')} {row.get('Notes','')}"
        })

layer = {
    'name': 'Cyberion ATT&CK Coverage',
    'versions': {'attack': '14', 'navigator': '4.9.1', 'layer': '4.5'},
    'domain': 'enterprise-attack',
    'description': 'Coverage from detection engineering engagement',
    'techniques': techniques,
    'gradient': {
        'colors': ['#ff0000', '#ffff00', '#00ff00'],
        'minValue': 0,
        'maxValue': 100
    }
}

out_path.write_text(json.dumps(layer, indent=2))
print(f'wrote {out_path}')
