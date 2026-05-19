# CookieVigil – Audit OWASP des cookies web

[![CI](https://github.com/tonuser/cookie-vigil-demo/actions/workflows/cookievigil.yml/badge.svg)](https://github.com/tonuser/cookie-vigil-demo/actions)

CookieVigil analyse les cookies selon 11 règles OWASP, génère des rapports (JSON, HTML, CSV, MD) et s’intègre en CI/CD.

## Architecture réelle (mémoire)
- VM1 : application vulnérable (Flask)
- VM2 : CookieVigil

## Démonstration reproductible (Docker)
```bash
docker-compose up
Usage local
bash
python audit_cookies.py https://example.com
Intégration DevSecOps
Options --fail-on et --fail-score-below.

Tests
bash
python -m pytest tests/
Voir SECURITY.md pour les limites.
