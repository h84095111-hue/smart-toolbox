from dataclasses import dataclass
from datetime import datetime, timezone
import json, uuid

@dataclass
class Evidence:
    case_id: str
    source: str
    title: str
    url: str = ''
    content: str = ''
    observed_at: str = ''
    confidence: str = 'Medium'
    kind: str = 'Observation'
    id: str = ''
    def __post_init__(self):
        if not self.id: self.id = str(uuid.uuid4())
        if not self.observed_at: self.observed_at = datetime.now(timezone.utc).isoformat()

@dataclass
class Finding:
    title: str
    value: str
    source: str
    url: str = ''
    confidence: str = 'Medium'
