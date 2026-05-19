#!/usr/bin/env python3
"""
VM1 - Application Web vulnérable
Serveur Flask avec base de données SQLite pour stocker les cookies
Interface utilisateur modernisée (sans emojis), adaptée pour CookieVigil.
Ajout des routes pour tester WEAK_TOKEN, JWT_DETECTED, expiration longue/courte.
"""

import sqlite3
import json
import secrets
from datetime import datetime
from flask import Flask, make_response, request, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = 'cookies.db'

# ==================== BASE DE DONNÉES ====================

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cookie_name TEXT NOT NULL,
            cookie_value TEXT NOT NULL,
            cookie_attributes TEXT,
            username TEXT,
            source_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("[+] Base de données initialisée")

def save_cookie(cookie_name, cookie_value, cookie_attributes, username="anonymous", source_url=""):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cookies (cookie_name, cookie_value, cookie_attributes, username, source_url)
        VALUES (?, ?, ?, ?, ?)
    ''', (cookie_name, cookie_value, json.dumps(cookie_attributes), username, source_url))
    conn.commit()
    conn.close()
    return True

def get_all_cookies():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT cookie_name, cookie_value, cookie_attributes, username, source_url, created_at FROM cookies')
    results = cursor.fetchall()
    conn.close()
    return results

def generate_session_token():
    return secrets.token_hex(32)

def generate_tracking_id():
    return f"track_{secrets.token_hex(16)}"

def generate_user_token():
    return f"user_{secrets.token_hex(16)}"

# ==================== ROUTES ====================

@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CookieVigil Lab - Application de démonstration</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            header {
                background: #2c3e50;
                color: white;
                padding: 30px;
                text-align: center;
            }
            header h1 { font-size: 2.5rem; margin-bottom: 10px; }
            header p { opacity: 0.9; font-size: 1.1rem; }
            .content { padding: 40px; }
            .badge {
                display: inline-block;
                background: #e74c3c;
                color: white;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                margin-right: 10px;
            }
            .card-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin-top: 30px;
            }
            .card {
                background: #f8f9fa;
                border-radius: 15px;
                padding: 25px;
                transition: transform 0.3s, box-shadow 0.3s;
                box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            }
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 30px rgba(0,0,0,0.1);
            }
            .card h3 {
                color: #2c3e50;
                margin-bottom: 15px;
                border-left: 4px solid #667eea;
                padding-left: 15px;
            }
            .card p {
                color: #555;
                line-height: 1.6;
                margin-bottom: 20px;
            }
            .btn {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                transition: background 0.3s;
                font-weight: 500;
            }
            .btn:hover { background: #5a67d8; }
            .btn-danger { background: #e74c3c; }
            .btn-danger:hover { background: #c0392b; }
            .btn-success { background: #27ae60; }
            .btn-success:hover { background: #229954; }
            footer {
                background: #2c3e50;
                color: #bdc3c7;
                text-align: center;
                padding: 20px;
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>CookieVigil Lab</h1>
                <p>Application de démonstration pour l'outil d'audit de cookies</p>
                <p><span class="badge">Version volontairement vulnérable</span> <span class="badge" style="background:#27ae60;">Cookies dynamiques</span></p>
            </header>
            <div class="content">
                <h2>Bienvenue sur la plateforme de test</h2>
                <p>Cette application simule un environnement réel comportant des failles de sécurité volontaires dans la gestion des cookies. Utilisez <strong>CookieVigil</strong> pour analyser les cookies et détecter les vulnérabilités.</p>
                
                <div class="card-grid">
                    <div class="card">
                        <h3>Authentification</h3>
                        <p>Testez la connexion avec un compte administrateur. Des cookies de session seront générés après authentification.</p>
                        <a href="/login" class="btn">Se connecter →</a>
                    </div>
                    <div class="card">
                        <h3>Cookies non sécurisés</h3>
                        <p>Génère des cookies dépourvus d'attributs de sécurité (Secure, HttpOnly, SameSite).</p>
                        <a href="/set-bad-cookies" class="btn btn-danger">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Cookies sécurisés</h3>
                        <p>Exemple de cookies bien configurés selon les recommandations OWASP.</p>
                        <a href="/set-good-cookies" class="btn btn-success">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Dashboard protégé</h3>
                        <p>Zone réservée aux utilisateurs authentifiés. Nécessite le cookie de session.</p>
                        <a href="/dashboard" class="btn">Accéder →</a>
                    </div>
                    <div class="card">
                        <h3>API Cookies</h3>
                        <p>Consultez la base de données des cookies stockés (preuve de collecte).</p>
                        <a href="/api/cookies" class="btn">Voir l'API</a>
                    </div>
                    <div class="card">
                        <h3>Expiration longue</h3>
                        <p>Génère un cookie avec une durée de vie d'un an (EXPIRES_LONG).</p>
                        <a href="/set-long-expiry" class="btn">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Expiration courte</h3>
                        <p>Génère un cookie avec une durée de vie de 5 minutes (normal).</p>
                        <a href="/set-short-expiry" class="btn">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Token faible</h3>
                        <p>Cookie avec une valeur courte (abc123) – déclenche WEAK_TOKEN.</p>
                        <a href="/set-weak-token" class="btn btn-danger">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Cookie JWT</h3>
                        <p>Cookie contenant un JWT factice – déclenche JWT_DETECTED.</p>
                        <a href="/set-jwt-cookie" class="btn">Générer</a>
                    </div>
                    <div class="card">
                        <h3>Déconnexion</h3>
                        <p>Efface vos cookies de session.</p>
                        <a href="/logout" class="btn">Se déconnecter</a>
                    </div>
                </div>
            </div>
            <footer>
                <p>CookieVigil Lab – Application vulnérable pour tests d'audit de sécurité</p>
                <p>Cookies dynamiques générés à chaque requête | Base de données SQLite</p>
            </footer>
        </div>
    </body>
    </html>
    """

@app.route('/login', methods=['GET'])
def login_form():
    return """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Connexion - CookieVigil Lab</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 450px;
                overflow: hidden;
            }
            .login-header {
                background: #2c3e50;
                color: white;
                padding: 30px;
                text-align: center;
            }
            .login-header h1 { font-size: 2rem; margin-bottom: 10px; }
            .login-body { padding: 40px; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; color: #2c3e50; font-weight: 500; }
            input {
                width: 100%;
                padding: 12px 15px;
                border: 1px solid #ddd;
                border-radius: 10px;
                font-size: 1rem;
                transition: border 0.3s;
            }
            input:focus { outline: none; border-color: #667eea; }
            button {
                width: 100%;
                padding: 12px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 25px;
                font-size: 1rem;
                font-weight: bold;
                cursor: pointer;
                transition: background 0.3s;
            }
            button:hover { background: #5a67d8; }
            .info {
                margin-top: 20px;
                text-align: center;
                font-size: 0.9rem;
                color: #7f8c8d;
            }
            .info strong { color: #2c3e50; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>Connexion</h1>
                <p>Accédez au tableau de bord</p>
            </div>
            <div class="login-body">
                <form method="POST" action="/login">
                    <div class="form-group">
                        <label>Nom d'utilisateur</label>
                        <input type="text" name="username" required autofocus>
                    </div>
                    <div class="form-group">
                        <label>Mot de passe</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit">Se connecter</button>
                </form>
                <div class="info">
                    <p>Compte de test : <strong>admin</strong> / <strong>admin123</strong></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', 'unknown')
    password = request.form.get('password', '')
    
    if username == "admin" and password == "admin123":
        response = make_response("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="refresh" content="2;url=/dashboard">
            <title>Connexion réussie</title>
            <style>
                body {
                    font-family: 'Segoe UI', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .card {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    text-align: center;
                }
                h1 { color: #27ae60; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Connexion réussie !</h1>
                <p>Redirection vers le tableau de bord...</p>
            </div>
        </body>
        </html>
        """)
        session_token = generate_session_token()
        response.set_cookie('session_token', session_token, 
                           httponly=True, secure=True, samesite='Lax')
        response.set_cookie('username', username, httponly=True)
        save_cookie('session_token', session_token, 
                   {'httponly': True, 'secure': True, 'samesite': 'Lax'}, 
                   username, "/login")
        save_cookie('username', username, 
                   {'httponly': True}, 
                   username, "/login")
        return response
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Échec de connexion</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 20px;
                text-align: center;
                max-width: 400px;
            }
            h1 { color: #e74c3c; }
            a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Échec de connexion</h1>
            <p>Identifiants incorrects.</p>
            <a href="/login">→ Réessayer</a>
        </div>
    </body>
    </html>
    """, 401

@app.route('/dashboard')
def dashboard():
    session_token = request.cookies.get('session_token')
    username = request.cookies.get('username')
    
    if session_token:
        return f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard - CookieVigil Lab</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                }}
                header {{
                    background: #2c3e50;
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .content {{ padding: 40px; }}
                .welcome {{
                    background: #ecf0f1;
                    padding: 20px;
                    border-radius: 15px;
                    margin-bottom: 30px;
                }}
                .btn {{
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    padding: 10px 20px;
                    border-radius: 25px;
                    text-decoration: none;
                    margin-top: 20px;
                }}
                .btn:hover {{ background: #5a67d8; }}
                footer {{
                    background: #2c3e50;
                    color: #bdc3c7;
                    text-align: center;
                    padding: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Tableau de bord</h1>
                    <p>Zone réservée aux utilisateurs authentifiés</p>
                </header>
                <div class="content">
                    <div class="welcome">
                        <h2>Bienvenue, {username} !</h2>
                        <p>Votre session est active. Vous pouvez maintenant analyser les cookies avec CookieVigil.</p>
                    </div>
                    <p>Les cookies de session suivants ont été générés :</p>
                    <ul style="margin: 20px 0 0 30px;">
                        <li><code>session_token</code> (Secure, HttpOnly, SameSite=Lax)</li>
                        <li><code>username</code> (HttpOnly)</li>
                    </ul>
                    <a href="/" class="btn">← Retour à l'accueil</a>
                </div>
                <footer>
                    <p>CookieVigil Lab – Démonstration de cookies post-authentification</p>
                </footer>
            </div>
        </body>
        </html>
        """
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Accès refusé</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 20px;
                text-align: center;
            }
            h1 { color: #e74c3c; }
            a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Accès non autorisé</h1>
            <p>Vous devez vous connecter pour accéder à cette page.</p>
            <a href="/login">→ Se connecter</a>
        </div>
    </body>
    </html>
    """, 401

@app.route('/set-bad-cookies')
def set_bad_cookies():
    session_value = secrets.token_hex(32)
    tracking_value = generate_tracking_id()
    user_value = generate_user_token()

    response = make_response(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Cookies non sécurisés</title>
        <style>
            body {{
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                padding: 30px;
                border-radius: 20px;
                max-width: 600px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            }}
            h1 {{ color: #e74c3c; }}
            code {{ background: #f1f1f1; padding: 2px 6px; border-radius: 4px; }}
            .btn {{
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookies non sécurisés définis</h1>
            <p>Les cookies suivants ont été créés sans attributs de sécurité :</p>
            <ul>
                <li><strong>session_insecure</strong> : <code>{session_value[:20]}...</code> (CRITICAL)</li>
                <li><strong>tracking</strong> : <code>{tracking_value}</code> (MEDIUM – domaine trop large simulé en base)</li>
                <li><strong>user_data</strong> : <code>{user_value}</code> (LOW)</li>
            </ul>
            <p><em>Chaque rafraîchissement génère de nouvelles valeurs uniques.</em></p>
            <a href="/" class="btn">← Retour à l'accueil</a>
        </div>
    </body>
    </html>
    """)

    # Cookie 1 : CRITICAL - Pas de Secure, pas de HttpOnly
    response.set_cookie('session_insecure', session_value, httponly=False, secure=False)
    # Cookie 2 : MEDIUM - Domaine trop large (simulé en base, cookie réel sans domain pour qu'il soit accepté)
    response.set_cookie('tracking', tracking_value, httponly=False, secure=False, path='/')
    # Cookie 3 : LOW - Path trop large
    response.set_cookie('user_data', user_value, path='/', httponly=False)

    save_cookie('session_insecure', session_value, {'httponly': False, 'secure': False}, "anonymous", "/set-bad-cookies")
    save_cookie('tracking', tracking_value, {'domain': '.example.com', 'httponly': False}, "anonymous", "/set-bad-cookies")
    save_cookie('user_data', user_value, {'path': '/', 'httponly': False}, "anonymous", "/set-bad-cookies")

    return response

@app.route('/set-good-cookies')
def set_good_cookies():
    secure_token = secrets.token_hex(32)
    response = make_response(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Cookies sécurisés</title>
        <style>
            body {{
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .card {{
                background: white;
                padding: 30px;
                border-radius: 20px;
                max-width: 500px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            }}
            h1 {{ color: #27ae60; }}
            .btn {{
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookies sécurisés définis</h1>
            <p>Cookie bien configuré selon OWASP :</p>
            <ul>
                <li><strong>session_secure</strong> : <code>{secure_token[:20]}...</code> (Secure, HttpOnly, SameSite=Lax)</li>
            </ul>
            <a href="/" class="btn">← Retour à l'accueil</a>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('session_secure', secure_token, httponly=True, secure=True, samesite='Lax')
    save_cookie('session_secure', secure_token, {'httponly': True, 'secure': True, 'samesite': 'Lax'}, "anonymous", "/set-good-cookies")
    return response

@app.route('/set-long-expiry')
def set_long_expiry():
    token = secrets.token_hex(32)
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Cookie longue durée</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .card {
                background: white;
                padding: 30px;
                border-radius: 20px;
                text-align: center;
            }
            .btn {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookie longue durée</h1>
            <p>Ce cookie a une expiration d'un an. Il devrait déclencher la règle EXPIRES_LONG.</p>
            <a href="/" class="btn">← Retour</a>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('long_lived_token', token, max_age=31536000, httponly=True, secure=True)
    save_cookie('long_lived_token', token, {'max-age': 31536000, 'httponly': True, 'secure': True}, "anonymous", "/set-long-expiry")
    return response

@app.route('/set-short-expiry')
def set_short_expiry():
    token = secrets.token_hex(32)
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Cookie courte durée</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .card {
                background: white;
                padding: 30px;
                border-radius: 20px;
                text-align: center;
            }
            .btn {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookie courte durée</h1>
            <p>Ce cookie a une expiration de 5 minutes. Il ne devrait PAS déclencher EXPIRES_LONG.</p>
            <a href="/" class="btn">← Retour</a>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('short_lived_token', token, max_age=300, httponly=True, secure=True)
    save_cookie('short_lived_token', token, {'max-age': 300, 'httponly': True, 'secure': True}, "anonymous", "/set-short-expiry")
    return response

# ==================== NOUVELLES ROUTES ====================

@app.route('/set-weak-token')
def set_weak_token():
    weak_value = "abc123"
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Token faible</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .card {
                background: white;
                padding: 30px;
                border-radius: 20px;
                text-align: center;
            }
            .btn {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookie avec token faible</h1>
            <p>Cookie <code>weak_session</code> créé avec la valeur <code>abc123</code> (courte et prévisible).</p>
            <p>Cette configuration devrait déclencher la règle <strong>WEAK_TOKEN</strong> (HIGH).</p>
            <a href="/" class="btn">← Retour</a>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('weak_session', weak_value, httponly=False, secure=False, path='/')
    save_cookie('weak_session', weak_value, {'httponly': False, 'secure': False}, "anonymous", "/set-weak-token")
    return response

@app.route('/set-jwt-cookie')
def set_jwt_cookie():
    jwt_value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Cookie JWT</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .card {
                background: white;
                padding: 30px;
                border-radius: 20px;
                text-align: center;
            }
            .btn {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                text-decoration: none;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Cookie contenant un JWT</h1>
            <p>Cookie <code>jwt_token</code> créé avec un JWT factice (trois parties séparées par des points).</p>
            <p>Cette configuration devrait déclencher la règle <strong>JWT_DETECTED</strong> (INFO).</p>
            <a href="/" class="btn">← Retour</a>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('jwt_token', jwt_value, httponly=False, secure=False, path='/')
    save_cookie('jwt_token', jwt_value, {'httponly': False, 'secure': False}, "anonymous", "/set-jwt-cookie")
    return response

@app.route('/logout')
def logout():
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="2;url=/">
        <title>Déconnexion</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 20px;
                text-align: center;
            }
            h1 { color: #3498db; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Déconnecté</h1>
            <p>Redirection vers l'accueil...</p>
        </div>
    </body>
    </html>
    """)
    response.set_cookie('session_token', '', expires=0)
    response.set_cookie('username', '', expires=0)
    return response

# ==================== API ====================

@app.route('/api/cookies', methods=['GET'])
def api_list_cookies():
    cookies = get_all_cookies()
    result = []
    for cookie in cookies:
        result.append({
            'name': cookie[0],
            'value': cookie[1][:50] + "..." if len(cookie[1]) > 50 else cookie[1],
            'attributes': json.loads(cookie[2]) if cookie[2] else {},
            'username': cookie[3],
            'source': cookie[4],
            'timestamp': cookie[5]
        })
    return jsonify({'count': len(result), 'cookies': result})

@app.route('/api/verify-cookie', methods=['POST'])
def api_verify_cookie():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    cookie_value = data.get('value')
    cookie_name = data.get('name')
    if not cookie_value:
        return jsonify({'error': 'Missing cookie value'}), 400
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    if cookie_name:
        cursor.execute('SELECT cookie_name, cookie_value, username, created_at FROM cookies WHERE cookie_name = ? AND cookie_value = ?', (cookie_name, cookie_value))
    else:
        cursor.execute('SELECT cookie_name, cookie_value, username, created_at FROM cookies WHERE cookie_value = ?', (cookie_value,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return jsonify({'exists': True, 'verified': True, 'cookie_name': result[0], 'username': result[2], 'timestamp': result[3], 'message': 'Cookie VERIFIE - Provient du serveur VM1'})
    else:
        return jsonify({'exists': False, 'verified': False, 'message': 'Cookie non trouve dans la base de donnees'})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'database': DATABASE, 'service': 'VM1 Vulnerable App'})

if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("VM1 - Application Vulnérable v2.0 (CookieVigil)")
    print("=" * 60)
    print("[*] Mode: Cookies DYNAMIQUES")
    print("[*] Routes disponibles :")
    print("    /set-long-expiry  → cookie avec expiration 1 an (EXPIRES_LONG)")
    print("    /set-short-expiry → cookie avec expiration 5 minutes")
    print("    /set-weak-token   → cookie avec token faible (WEAK_TOKEN)")
    print("    /set-jwt-cookie   → cookie contenant un JWT (JWT_DETECTED)")
    print("[*] Base de données: cookies.db")
    print("[*] API de vérification: /api/verify-cookie")
    print("[*] Liste des cookies: /api/cookies")
    print("[*] Serveur démarré sur http://0.0.0.0:5000")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=5000)
