# 🍪 CookieSentinel - Démonstration CI/CD

[![CookieSentinel Audit](https://github.com/edmond2003/cookie-sentinel-demo/actions/workflows/cookie-sentinel-audit.yml/badge.svg)](https://github.com/edmond2003/cookie-sentinel-demo/actions/workflows/cookie-sentinel-audit.yml)

## 📋 Description

Ce dépôt démontre l'intégration de **CookieSentinel v2.0**, un outil d'audit automatisé de sécurité des cookies, dans un pipeline CI/CD DevSecOps.

## 🎯 Nouvelles fonctionnalités de la v2.0

- ✅ Détection des **cookies sensibles** (session, auth, token)
- ✅ Rapports enrichis (JSON, HTML, CSV, MD)
- ✅ Option `--insecure` pour les environnements de test
- ✅ Vérification SSL par défaut
- ✅ 9 règles OWASP complètes
- ✅ 35 tests unitaires
- ✅ **Security Gate** (échec du pipeline si vulnérabilités CRITICAL)

## 🔄 Pipeline CI/CD

Le pipeline s'exécute automatiquement lors des événements suivants :

- ✅ **Push** sur les branches main/master
- ✅ **Pull Request** vers main/master
- ⏰ **Schedule** : tous les jours à 2h
- 🖱️ **Manuellement** via GitHub Actions

### Security Gate

| Code de retour | Signification | Action |
|----------------|---------------|--------|
| 0 | Succès, aucune vulnérabilité critique | Pipeline continue ✅ |
| 1 | Vulnérabilités HIGH détectées | Pipeline échoue ❌ |
| 2 | Vulnérabilités CRITICAL détectées | Pipeline échoue ❌ |

## 📊 Détection des vulnérabilités

| Vulnérabilité | Niveau | Détection |
|---------------|--------|-----------|
| Secure manquant | CRITICAL | ✅ |
| HttpOnly manquant | HIGH | ✅ |
| SameSite=None sans Secure | CRITICAL | ✅ |
| Domaine trop large | MEDIUM | ✅ |
| Path trop large | LOW | ✅ |
| Cookies sensibles | INFO | ✅ |

## 🚀 Exécution locale

```bash
# Installation
pip install -r requirements.txt

# Audit avec SSL (recommandé)
python audit_cookies.py https://exemple.com

# Audit sans SSL (tests uniquement)
python audit_cookies.py --insecure https://exemple.com
