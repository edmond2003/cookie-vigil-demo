# Rapport d'analyse des cookies

**Date :** 2026-03-16 09:01:39

## Résumé

- **Total cookies :** 4
- **Cookies sécurisés :** 0
- **Cookies non sécurisés :** 4

### Répartition par risque

- **CRITICAL :** 0
- **HIGH :** 1
- **MEDIUM :** 3
- **LOW :** 0
- **INFO :** 0

## Détail des cookies

### 🍪 __Secure-STRP (HIGH)

**Attributs :**

- domain: .google.com
- path: /
- expires: Mon, 16-Mar-2026 08:06:18 GMT
- max-age: 
- secure: True
- httponly: False
- samesite: strict

**Problèmes détectés :**

- ⚠️ **Attribut HttpOnly manquant** (HIGH)
  - Le cookie est accessible via JavaScript (risque XSS)
  - 💡 *Ajouter l'attribut "HttpOnly" pour empêcher l'accès JavaScript*
- ⚠️ **Domaine trop large** (MEDIUM)
  - Le cookie est envoyé à tous les sous-domaines
  - 💡 *Limiter le domaine au minimum nécessaire, éviter les domaines commençant par "."*
- ⚠️ **Path trop large** (LOW)
  - Le cookie est envoyé sur tout le site
  - 💡 *Restreindre le path au strict nécessaire*

---

### 🍪 AEC (MEDIUM)

**Attributs :**

- domain: .google.com
- path: /
- expires: Sat, 12-Sep-2026 08:01:18 GMT
- max-age: 
- secure: True
- httponly: True
- samesite: lax

**Problèmes détectés :**

- ⚠️ **Domaine trop large** (MEDIUM)
  - Le cookie est envoyé à tous les sous-domaines
  - 💡 *Limiter le domaine au minimum nécessaire, éviter les domaines commençant par "."*
- ⚠️ **Path trop large** (LOW)
  - Le cookie est envoyé sur tout le site
  - 💡 *Restreindre le path au strict nécessaire*

---

### 🍪 NID (MEDIUM)

**Attributs :**

- domain: .google.com
- path: /
- expires: Tue, 15-Sep-2026 08:01:18 GMT
- max-age: 
- secure: True
- httponly: True
- samesite: none

**Problèmes détectés :**

- ⚠️ **Domaine trop large** (MEDIUM)
  - Le cookie est envoyé à tous les sous-domaines
  - 💡 *Limiter le domaine au minimum nécessaire, éviter les domaines commençant par "."*
- ⚠️ **Path trop large** (LOW)
  - Le cookie est envoyé sur tout le site
  - 💡 *Restreindre le path au strict nécessaire*

---

### 🍪 __Secure-BUCKET (MEDIUM)

**Attributs :**

- domain: .google.com
- path: /
- expires: Sat, 12-Sep-2026 08:01:18 GMT
- max-age: 
- secure: True
- httponly: True
- samesite: 

**Problèmes détectés :**

- ⚠️ **Attribut SameSite manquant** (MEDIUM)
  - Protection CSRF insuffisante
  - 💡 *Ajouter "SameSite=Lax" ou "SameSite=Strict" selon le besoin*
- ⚠️ **Domaine trop large** (MEDIUM)
  - Le cookie est envoyé à tous les sous-domaines
  - 💡 *Limiter le domaine au minimum nécessaire, éviter les domaines commençant par "."*
- ⚠️ **Path trop large** (LOW)
  - Le cookie est envoyé sur tout le site
  - 💡 *Restreindre le path au strict nécessaire*

---

