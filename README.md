# 🍪 CookieSentinel - Démonstration CI/CD

[![CookieSentinel Audit](https://github.com/edmond2003/cookie-sentinel-demo/actions/workflows/cookie-sentinel-audit.yml/badge.svg)](https://github.com/edmond2083/cookie-sentinel-demo/actions/workflows/cookie-sentinel-audit.yml)

## 📋 Description

Ce dépôt démontre l'intégration de **CookieSentinel**, un outil d'audit automatisé de sécurité des cookies, dans un pipeline CI/CD DevSecOps.

## 🎯 Objectif

Détecter automatiquement les vulnérabilités liées aux cookies (Secure, HttpOnly, SameSite, etc.) à chaque étape du cycle de développement.

## 🔄 Pipeline CI/CD

Le pipeline s'exécute automatiquement lors des événements suivants :

- ✅ **Push** sur les branches main/master
- ✅ **Pull Request** vers main/master
- ⏰ **Schedule** : tous les jours à 2h du matin
- 🖱️ **Manuellement** via GitHub Actions

## 📊 Ce que CookieSentinel détecte

| Vulnérabilité | Niveau de risque | Description |
|---------------|------------------|-------------|
| Secure manquant | CRITICAL | Cookie transmis en clair sur HTTP |
| HttpOnly manquant | HIGH | Cookie accessible via JavaScript (XSS) |
| SameSite manquant | MEDIUM | Protection CSRF insuffisante |
| Domaine trop large | MEDIUM | Cookie partagé sur trop de sous-domaines |
| Path trop large | LOW | Cookie envoyé sur trop de chemins |

## 🚀 Exécution locale

```bash
# Installation
pip install -r requirements.txt

# Audit d'un site
python audit_cookies.py https://exemple.com

# Audit avec rapport HTML
python audit_cookies.py https://exemple.com --format html
