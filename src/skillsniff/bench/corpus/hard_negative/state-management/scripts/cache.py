import json
from pathlib import Path

CACHE = Path(__file__).parent / '.cache' / 'lookups.json'


def save(data):
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(data))
