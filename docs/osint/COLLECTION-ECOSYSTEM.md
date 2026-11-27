# Collection ecosystem and provider reliability

## Provider catalogue

`smartintel.source_catalog` provides a metadata catalogue of 40+ candidate
sources across certificate transparency, web archives, threat intelligence,
passive DNS, breach notifications, corporate records, sanctions, courts,
WHOIS history, username presence, social monitoring, aviation, maritime,
document metadata and reverse-image search.

**Catalogue presence does not mean an integration exists.** Entries are
explicitly marked `implemented`, `planned`, `licensed`, or `manual`.
The current catalogue intentionally marks only connectors already represented
in the existing passive collector implementation as implemented. Licensed
sources require separate procurement and contract review.

## Adapter reliability

`AdapterManager` provides:
- bounded retries with exponential backoff and jitter;
- per-provider success/failure health counters;
- circuit breaking after repeated failures;
- structural response fingerprints and schema-drift alerts;
- explicit health reports for UI/monitoring.

Schema drift is detected, not silently "fixed". Automatic field guessing can
mislabel evidence. A provider adapter should be updated, reviewed, and covered
by fixture tests before its output is trusted again.

## Collection policy

- Prefer official APIs, documented feeds, and licensed datasets.
- HIBP-style breach checks require an authenticated, terms-compliant workflow;
  do not retrieve or expose stolen passwords or credential dumps.
- Social, forum, Telegram, and dark-web collection must use lawful, permitted
  access methods and remain within documented case scope.
- Reverse-image search is an operator-mediated link-out where no supported
  official API exists. EXIF and document metadata extraction can run locally.
- Face matching and identity assertions are not enabled by this catalogue.
- Username/email/phone presence results are leads, not identity verification.
- Provider terms, rate limits, privacy law, retention rules, and licensing
  requirements apply independently of whether a connector is technically
  available.

## Current limitation

This catalogue and reliability layer do not add 40 live integrations. Most
listed sources are roadmap metadata. A connector is only operational after
implementation, credentials/configuration, fixtures, tests, and a documented
data-handling review.
