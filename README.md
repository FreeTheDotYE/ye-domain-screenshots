# .YE domain screenshot evidence

This repository preserves day-precision screenshots of publicly reachable
websites reached through names in Yemen's Houthi-controlled `.YE` namespace.
It is part of the [FreeTheDotYE](https://freethedotye.org/) evidence platform.

The collection is designed to answer a narrow, verifiable question: what did a
public web service reached through a particular `.YE` domain visibly return
from an external network vantage on a recorded day?

## Evidence model

- `current.jsonl` points to the latest successful screenshot for each domain.
- `observations/YYYY/MM.jsonl` is append-only and records a first or changed
  screenshot.
- `images/sha256/` stores content-addressed JPEG files. An unchanged image is
  not duplicated.
- `runs/latest.json` reports coverage for the latest bounded collection run.
- `MANIFEST.sha256` covers every published file except the manifest itself.

The current collector stores a full-page JPEG at a fixed 1365-pixel layout
width and records the actual image height. Early 1365 x 768 viewport-only
observations remain in append-only history; current rows are recaptured in the
full-page format. The public ledger shows a cropped responsive preview that
links to the complete content-addressed image.

The collector revisits the public corpus incrementally and prioritizes names
without a screenshot and names with newly confirmed DNS changes. Exact
collection times and private operational diagnostics are not published.

A screenshot is published only after a successful HTTP response carrying web
page content and a completed browser capture. A failed external attempt is not
published as proof that a site is globally offline: a failure can result from
DNS, TLS, application behavior, rate limiting, filtering, or restrictions on
traffic originating outside Yemen.

## Public row fields

Every current row records the domain, requested and final URL, HTTP status,
content type, image digest and path, capture day, most recent successful check
day, fixed capture width, and actual full-page height. Observation identifiers
are SHA-256 digests of their canonical public payload.

All dates are UTC calendar dates. The data records observations, not inferred
registration dates, ownership, or a complete service-availability history.

## Validation

Run:

```sh
python3 scripts/validate.py
```

Validation checks canonical JSONL ordering, identifiers, image digests and
paths, run totals, current-to-history reconciliation, and the repository-wide
