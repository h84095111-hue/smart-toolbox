# Security and evidence handling

## Local data

Case data is stored under `~/.smart-intel/data/` in SQLite. The Fernet helper in `smartintel/evidence_integrity.py` is a building block only; the database and attachments are not yet automatically encrypted at rest.

## API keys

The desktop app uses Python keyring for AI and supported OSINT API keys. Never hardcode secrets or commit them to Git. Use least-privilege keys, rotate exposed keys and review provider retention/data-processing terms.

## Audit journal

Case creation and evidence additions are appended to a JSONL hash chain in `~/.smart-intel/audit.jsonl`. The helper verifies chain integrity. This is tamper-evident against accidental edits, not immutable storage: a privileged user can rewrite the file and recompute hashes. Independent signing, trusted timestamps and verification UI remain future work.

## AI disclosure

Cloud AI analysis sends selected evidence to the chosen provider API. Do not submit confidential, regulated or personal data without lawful basis and authorization. AI results are suggestions, not facts.

## Collection boundaries

No port scanning, service fingerprinting, exploitation, authentication attempts, credential stuffing, private-account scraping or access-control bypass. Provider APIs query data already held by providers. Follow acceptable-use terms and rate limits.

## Incident response

If an API key is exposed, revoke it with the provider, remove it from repository history where appropriate and replace it. If evidence may have been altered, preserve copies of the database and audit journal before investigating.
