# SiteGuard

SiteGuard is a production-minded Python CLI for finding potential fraudulent or lookalike websites and subdomains for a protected brand or person name.

## File/folder structure

```text
siteguard/
  cli.py          # argparse entry point
  generator.py    # dnstwist permutations and subdomain candidate generation
  discoverer.py   # crt.sh, DNS brute-force, optional Google CSE discovery
  collector.py    # DNS, WHOIS, TLS, title/meta enrichment
  scorer.py       # configurable fraud-likelihood scoring
  reporter.py     # Rich console table and JSON output
  config.py       # YAML config loading helpers
  models.py       # typed dataclasses
  net.py          # rate limiting and retry helpers
tests/
  test_scorer.py  # scorer unit tests
config.yaml       # scoring weights, thresholds, network controls, subdomain words
requirements.txt
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional Google Custom Search support is configured through `.env`:

```env
GOOGLE_API_KEY=your_free_tier_key
GOOGLE_CSE_ID=your_custom_search_engine_id
```

If either value is missing, SiteGuard logs that Google Custom Search is skipped and continues with free crt.sh and DNS discovery.

## Usage

```bash
python -m siteguard --name "BrandName" --output report.json
```

If installed as a package wrapper, expose `siteguard.cli:main` as the `siteguard` console script and run:

```bash
siteguard --name "BrandName" --output report.json
```

## Discovery approach

SiteGuard uses multiple discovery vectors:

1. **Permutation generation** with `dnstwist` for typosquats, homoglyphs, hyphenation, and TLD swaps.
2. **Certificate Transparency** through crt.sh's free JSON endpoint (`https://crt.sh/?q=%25{name}%25&output=json`) to catch public certificates containing the protected name, including subdomains on unrelated parent domains.
3. **DNS brute force** of configured words such as `login`, `secure`, `verify`, `account`, `portal`, and `my` against the real domain and generated permutations.
4. **Optional Google Custom Search** to catch brand mentions in page content or titles where hostnames have no obvious similarity.

Every outbound operation is bounded by configured timeouts, rate limits, retries, and backoff. Failures are logged and attached to findings where relevant; a single failed lookup does not stop the batch.

## Scoring logic

`siteguard/scorer.py` computes a 0-100 fraud-likelihood score from component scores weighted in `config.yaml`, not hardcoded constants:

```yaml
scoring:
  weights:
    levenshtein_similarity: 25
    domain_age: 20
    brand_content_presence: 20
    ssl_issuer_reputation: 15
    discovery_source: 20
```

Current component meanings:

- **Levenshtein similarity**: compares the protected name to the first hostname label, after normalization. Very similar labels score higher.
- **Domain age**: newer domains score higher; missing WHOIS age receives the configurable missing-data score.
- **Brand content presence**: title/meta description containing the protected name score higher.
- **SSL issuer reputation**: missing or unusual issuers score higher than common reputable issuers.
- **Discovery source**: source-specific risk is configurable. Certificate Transparency hits on unrelated domains are weighted as especially risky because they may indicate brand-themed infrastructure outside expected domains.

## Limitations / Coverage

SiteGuard performs multi-vector discovery (permutation + certificate transparency + DNS brute-force + optional search), but it is not exhaustive. Sites with no public DNS, no public certificate transparency footprint, no indexed search footprint, or infrastructure that appears only after scan time will not be found. WHOIS data can be incomplete or GDPR-redacted. Scoring is a prioritization aid, not a legal or definitive fraud determination.

## Testing

```bash
pytest
```
