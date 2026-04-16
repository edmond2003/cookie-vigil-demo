#!/usr/bin/env python3
"""
Application de démonstration volontairement vulnérable
Pour tester CookieSentinel dans le pipeline CI/CD
"""

from flask import Flask, make_response, request
import secrets

app = Flask(__name__)
app.secret_key = 'une_cle_tres_faible_pour_demo'

@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CookieSentinel - Application de démonstration</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; }
            h1 { color: #333; }
            .bad { color: red; }
            .good { color: green; }
            button { padding: 10px; margin: 5px; cursor: pointer; }
            code { background: #eee; padding: 2px 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🍪 CookieSentinel - Application de démonstration</h1>
            <p>Cette application est volontairement <strong class="bad">vulnérable</strong> pour tester l'outil d'audit.</p>
            
            <h2>Actions :</h2>
            <ul>
                <li><a href="/set-bad-cookies">🔴 Définir des cookies NON sécurisés</a></li>
                <li><a href="/set-good-cookies">🟢 Définir des cookies sécurisés</a></li>
                <li><a href="/check-cookies">🔍 Vérifier les cookies actuels</a></li>
                <li><a href="/clear-cookies">🗑️ Effacer tous les cookies</a></li>
            </ul>
            
            <h2>Vulnérabilités testées :</h2>
            <ul>
                <li>❌ <code>Secure</code> manquant (CRITICAL)</li>
                <li>❌ <code>HttpOnly</code> manquant (HIGH)</li>
                <li>❌ <code>SameSite</code> manquant (MEDIUM)</li>
                <li>❌ Domaine trop large <code>.example.com</code> (MEDIUM)</li>
                <li>❌ Path trop large <code>/</code> (LOW)</li>
            </ul>
        </div>
    </body>
    </html>
    """

@app.route('/set-bad-cookies')
def set_bad_cookies():
    """Définit des cookies volontairement non sécurisés"""
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head><title>Cookies non sécurisés</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1 style="color: red;">🔴 Cookies NON sécurisés définis !</h1>
        <p>Ces cookies présentent des vulnérabilités :</p>
        <ul>
            <li><strong>session_insecure</strong> : pas de Secure, pas de HttpOnly → <strong>CRITICAL + HIGH</strong></li>
            <li><strong>tracking</strong> : domaine trop large (.example.com) → <strong>MEDIUM</strong></li>
            <li><strong>user_data</strong> : path trop large (/) → <strong>LOW</strong></li>
        </ul>
        <h3>Vulnérabilités attendues :</h3>
        <ul>
            <li>❌ SECURE_MISSING (CRITICAL)</li>
            <li>❌ HTTPONLY_MISSING (HIGH)</li>
            <li>❌ DOMAIN_TOO_BROAD (MEDIUM)</li>
            <li>❌ PATH_TOO_BROAD (LOW)</li>
        </ul>
        <a href="/">← Retour à l'accueil</a>
    </body>
    </html>
    """)
    
    # Cookie 1 : Pas de Secure, pas de HttpOnly (CRITICAL + HIGH)
    response.set_cookie('session_insecure', 'valeur_sensible_123', 
                        httponly=False, secure=False)
    
    # Cookie 2 : Domaine trop large (MEDIUM)
    response.set_cookie('tracking', 'user_id_456', 
                        domain='.example.com', httponly=False)
    
    # Cookie 3 : Path trop large (LOW)
    response.set_cookie('user_data', 'info_publique', 
                        path='/', httponly=False)
    
    return response

@app.route('/set-good-cookies')
def set_good_cookies():
    """Définit des cookies sécurisés (bonnes pratiques OWASP)"""
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head><title>Cookies sécurisés</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1 style="color: green;">🟢 Cookies sécurisés définis !</h1>
        <p>Ces cookies suivent les bonnes pratiques OWASP :</p>
        <ul>
            <li><strong>session_secure</strong> : Secure, HttpOnly, SameSite=Lax</li>
        </ul>
        <a href="/">← Retour à l'accueil</a>
    </body>
    </html>
    """)
    
    # Cookie sécurisé selon OWASP
    response.set_cookie('session_secure', 'token_securise_789',
                        httponly=True, secure=True, samesite='Lax')
    
    return response

@app.route('/check-cookies')
def check_cookies():
    """Affiche les cookies actuels"""
    cookies = dict(request.cookies)
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Cookies actuels</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🔍 Cookies actuellement présents</h1>
        <ul>
    """
    if cookies:
        for name, value in cookies.items():
            html += f"<li><strong>{name}</strong> = {value[:50]}...</li>"
    else:
        html += "<li>Aucun cookie défini</li>"
    
    html += """
        </ul>
        <a href="/">← Retour à l'accueil</a>
    </body>
    </html>
    """
    return html

@app.route('/clear-cookies')
def clear_cookies():
    """Efface tous les cookies"""
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head><title>Cookies effacés</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🗑️ Tous les cookies ont été effacés</h1>
        <a href="/">← Retour à l'accueil</a>
    </body>
    </html>
    """)
    
    response.set_cookie('session_insecure', '', expires=0)
    response.set_cookie('tracking', '', expires=0)
    response.set_cookie('user_data', '', expires=0)
    response.set_cookie('session_secure', '', expires=0)
    
    return response

if __name__ == '__main__':
    print("🚀 Démarrage de l'application de démonstration...")
    print("📍 Accès: http://localhost:5000")
    print("🔬 Cette application contient des cookies volontairement vulnérables")
    app.run(debug=False, host='0.0.0.0', port=5000)
