# No-paid-API identity collection

Smart Intel's identity checks are intentionally split by what public, no-paid-API
sources can actually establish.

## Username checks (broadest coverage)

Install Maigret in the same Python environment as Smart Intel:

```bash
python -m pip install maigret
```

The identity engine invokes Maigret locally with its public site database,
defaults to 500 sites, supports a configurable limit up to 3,000, disables
recursive crawling inside Maigret, and emits normalized candidate-profile
findings. Maigret's database changes over time; the number actually checked
depends on the installed database, site filters, network reachability and
individual site behavior. The requested limit is not a guaranteed hit count.

The engine deliberately does not enable Cloudflare bypass, browser-cookie
reuse, or other challenge circumvention. Blocked, rate-limited and unknown
results must remain unknown—not be treated as "not found".

## Email checks (no API)

The built-in check validates syntax, inspects public mail-domain DNS when
dnspython is installed, and provides exact-match public search links. It does
not prove that a mailbox exists, perform SMTP VRFY/RCPT probing, search stolen
credential dumps, or retrieve private breach records. Public search results
are leads and must be manually verified.

## Phone checks (no API)

Install the optional offline parser:

```bash
python -m pip install phonenumbers
```

It normalizes numbers and checks numbering-plan plausibility, region and broad
line type. It does not identify a subscriber, verify current assignment, or
prove ownership. Public exact-match search links are provided for analyst-led
review.

## Profile parsing and pivots

`extract_profile_metadata` parses public HTML metadata, canonical URLs and
self-asserted `rel=me` links. These are evidence candidates, not verified
identity links. A downstream pivot workflow should preserve the source URL,
capture time, raw evidence hash and confidence, and require analyst approval
before expanding from a profile to a new identifier. Do not auto-pivot on
display-name similarity alone.

## Integration status

This module is wired into the PyQt6 integrations panel for username, email,
phone and public profile URL checks. The case graph and workflow runner do not
yet execute approved pivots automatically; the queue is a bounded approval
foundation. No API key is required for Maigret, email DNS inspection or
phonenumbers parsing.
