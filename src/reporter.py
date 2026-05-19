import json
import csv
from datetime import datetime
from typing import Dict, List
import os
from jinja2 import Template


class CookieReporter:
    """
    Générateur de rapports d'analyse de cookies.
    Supporte JSON, HTML, CSV et Markdown.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Template HTML avec section PREUVE
        self.html_template = Template("""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>CookieVigil - Rapport d'audit</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #0a0e17; color: #e4e4e4; }
        .container { max-width: 1400px; margin: auto; background: #141a24; padding: 25px; border-radius: 8px; }
        h1 { color: #61afef; border-bottom: 1px solid #3b4252; padding-bottom: 10px; }
        h2 { color: #98c379; margin-top: 25px; }
        h3 { color: #e5c07b; }
        h4 { color: #56b6c2; margin: 10px 0 5px 0; }
        .summary { background: #1e2632; padding: 20px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #61afef; }
        .cookie-card {
            border: 1px solid #2c3440;
            padding: 18px;
            margin: 15px 0;
            border-radius: 6px;
            background: #1a202c;
        }
        .risk-CRITICAL { border-left: 4px solid #e06c75; }
        .risk-HIGH { border-left: 4px solid #e5c07b; }
        .risk-MEDIUM { border-left: 4px solid #61afef; }
        .risk-LOW, .risk-INFO { border-left: 4px solid #98c379; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-family: monospace;
        }
        .badge.CRITICAL { background: #e06c75; color: #1a202c; }
        .badge.HIGH { background: #e5c07b; color: #1a202c; }
        .badge.MEDIUM { background: #61afef; color: #1a202c; }
        .badge.LOW, .badge.INFO { background: #98c379; color: #1a202c; }
        .sensitive-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            background: #e5c07b;
            color: #1a202c;
            font-size: 11px;
            margin-left: 10px;
            font-family: monospace;
        }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #2c3440; }
        th { background: #1e2632; color: #61afef; }
        .issue { background: #1e2632; padding: 12px; margin: 8px 0; border-left: 3px solid #e5c07b; }
        .proof-box {
            background: #0d1117;
            border: 1px solid #3b4252;
            border-radius: 4px;
            padding: 12px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
        }
        .proof-header {
            color: #98c379;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .proof-content {
            color: #abb2bf;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .verification-success {
            color: #98c379;
            font-weight: bold;
        }
        .verification-failed {
            color: #e06c75;
            font-weight: bold;
        }
        pre {
            background: #0d1117;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 11px;
        }
        code {
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>CookieVigil - Rapport d'audit de sécurité</h1>
        <p><strong>Généré le :</strong> {{ timestamp }}</p>

        <div class="summary">
            <h2>Resume Global</h2>
            <table>
                <tr><th>Total cookies analyses</th><td>{{ stats.total }}</td></tr>
                <tr><th>Cookies securises</th><td>{{ stats.secure_count }}</td></tr>
                <tr><th>Cookies non securises</th><td>{{ stats.insecure_count }}</td></tr>
                {% if stats.sensitive_count %}
                <tr style="background: #1e2632;"><th>Cookies SENSIBLES detectes</th><td><strong>{{ stats.sensitive_count }}</strong></td></tr>
                {% endif %}
            </table>

            <h3>Repartition par niveau de risque</h3>
            <table>
                {% for level, count in stats.risk_counts.items() %}
                <tr>
                    <td><span class="badge {{ level }}">{{ level }}</span></td>
                    <td><strong>{{ count }}</strong></td>
                </tr>
                {% endfor %}
            </table>

            {% if stats.security_score is defined %}
            <h3>Score de securite</h3>
            <div class="proof-box">
                <div class="proof-header">Score global</div>
                <div class="proof-content">{{ stats.security_score }}/100</div>
            </div>
            {% endif %}
        </div>

        <h2>Details des cookies analyses</h2>
        {% for result in results %}
        <div class="cookie-card risk-{{ result.risk_level }}">
            <h3>
                {{ result.cookie.name | e }}
                {% if result.is_sensitive %}
                <span class="sensitive-badge">SENSIBLE</span>
                {% endif %}
                <span class="badge {{ result.risk_level }}">{{ result.risk_level }}</span>
            </h3>

            <h4>Attributs du cookie</h4>
            <table>
                {% for key, value in (result.cookie.attributes or {}).items() %}
                <tr><th>{{ key | e }}</th><td>{{ value | default('Non defini') | e }}</td></tr>
                {% endfor %}
            </table>

            {% if result.cookie.value_length is defined or result.cookie.value_sha256 %}
            <h4>Metadonnees de valeur</h4>
            <table>
                {% if result.cookie.value_length is defined %}
                <tr><th>Longueur de la valeur</th><td>{{ result.cookie.value_length }}</td></tr>
                {% endif %}
                {% if result.cookie.value_sha256 %}
                <tr><th>SHA-256 de la valeur</th><td>{{ result.cookie.value_sha256 | e }}</td></tr>
                {% endif %}
            </table>
            {% endif %}

            <!-- CORRECTION :
                 La preuve de collecte est stockée dans result.cookie.proof,
                 pas directement dans result.proof. -->
            {% if result.cookie.proof %}
            <h4>Preuve de collecte</h4>
            <div class="proof-box">
                <div class="proof-header">Source</div>
                <div class="proof-content">URL: {{ result.cookie.proof.source_url | e }}</div>
                <div class="proof-content">Timestamp: {{ result.cookie.proof.timestamp | e }}</div>
                <div class="proof-content">Statut HTTP: {{ result.cookie.proof.response_status }}</div>
                <div class="proof-content">TLS verifie: {{ 'OUI' if result.cookie.proof.tls_verified else 'NON' }}</div>
                {% if result.cookie.proof.raw_header %}
                <div class="proof-header" style="margin-top: 10px;">En-tete brut Set-Cookie</div>
                <div class="proof-content"><pre>{{ result.cookie.proof.raw_header | e }}</pre></div>
                <div class="verification-success">Ce cookie provient directement du serveur web</div>
                {% endif %}
            </div>
            {% endif %}

            {% if result.issues %}
            <h4>Problemes detectes ({{ result.issues|length }})</h4>
            {% for issue in result.issues %}
            <div class="issue">
                <p><strong>{{ issue.name | e }}</strong> ({{ issue.risk }})</p>
                <p>{{ issue.description | e }}</p>
                <p><strong>Recommandation :</strong> {{ issue.recommendation | e }}</p>
            </div>
            {% endfor %}
            {% else %}
            <div class="verification-success" style="padding: 10px;">Ce cookie est bien configure selon OWASP</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """)

    def generate_report(self, analysis_result: Dict, fmt: str = "html", base_filename: str = None) -> str:
        """Génère un rapport dans le format demandé."""
        if not analysis_result:
            raise ValueError("analysis_result ne peut pas être vide")

        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_file = now.strftime("%Y%m%d_%H%M%S")

        if not base_filename:
            base_filename = f"cookie_audit_{timestamp_file}"

        stats = analysis_result.get('statistics', {})
        results = analysis_result.get('results', [])

        if fmt == "json":
            return self._generate_json(stats, results, base_filename, timestamp_str)
        elif fmt == "html":
            return self._generate_html(stats, results, base_filename, timestamp_str)
        elif fmt == "csv":
            return self._generate_csv(stats, results, base_filename)
        elif fmt == "md":
            return self._generate_markdown(stats, results, base_filename, timestamp_str)
        else:
            raise ValueError(f"Format non supporté : {fmt}")

    def _generate_json(self, stats: Dict, results: List, base_filename: str, timestamp: str) -> str:
        output = {
            'timestamp': timestamp,
            'statistics': stats,
            'cookies': results
        }
        filepath = os.path.join(self.output_dir, f"{base_filename}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        return filepath

    def _generate_html(self, stats: Dict, results: List, base_filename: str, timestamp: str) -> str:
        html_content = self.html_template.render(
            timestamp=timestamp,
            stats=stats,
            results=results
        )
        filepath = os.path.join(self.output_dir, f"{base_filename}.html")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filepath

    def _generate_csv(self, stats: Dict, results: List, base_filename: str) -> str:
        filepath = os.path.join(self.output_dir, f"{base_filename}.csv")

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'URL', 'Cookie', 'Sensible', 'Risque', 'Problemes', 'Recommandations',
                'Secure', 'HttpOnly', 'SameSite', 'Domain', 'Path',
                'Value_Length', 'Value_SHA256',
                'Source_URL', 'Timestamp'
            ])

            for result in results:
                cookie = result.get('cookie', {})
                attrs = cookie.get('attributes', {}) or {}
                issues = result.get('issues', [])

                # CORRECTION :
                # La preuve est stockée dans le cookie analysé.
                proof = cookie.get('proof', {})

                writer.writerow([
                    result.get('final_url', 'N/A'),
                    cookie.get('name', 'N/A'),
                    'OUI' if result.get('is_sensitive', False) else 'NON',
                    result.get('risk_level', 'INFO'),
                    '; '.join(i.get('name', '') for i in issues),
                    '; '.join(i.get('recommendation', '') for i in issues),
                    attrs.get('secure', False),
                    attrs.get('httponly', False),
                    attrs.get('samesite', ''),
                    attrs.get('domain', ''),
                    attrs.get('path', '/'),
                    cookie.get('value_length', ''),
                    cookie.get('value_sha256', ''),
                    proof.get('source_url', 'N/A'),
                    proof.get('timestamp', 'N/A')
                ])
        return filepath

    def _generate_markdown(self, stats: Dict, results: List, base_filename: str, timestamp: str) -> str:
        content = "# CookieVigil - Rapport d'audit\n\n"
        content += f"**Genere le :** {timestamp}\n\n"

        content += "## Resume\n\n"
        content += f"- **Total cookies :** {stats.get('total', 0)}\n"
        content += f"- **Cookies securises :** {stats.get('secure_count', 0)}\n"
        content += f"- **Cookies non securises :** {stats.get('insecure_count', 0)}\n"

        sensitive_count = stats.get('sensitive_count', 0)
        if sensitive_count > 0:
            content += f"- **Cookies SENSIBLES :** {sensitive_count}\n"

        if 'security_score' in stats:
            content += f"- **Score de securite :** {stats.get('security_score')}/100\n"

        content += "\n### Repartition par risque\n\n"
        for level, count in stats.get('risk_counts', {}).items():
            content += f"- **{level}**: {count} cookies\n"

        content += "\n## Details des cookies\n\n"

        for result in results:
            cookie = result.get('cookie', {})
            risk = result.get('risk_level', 'INFO')
            is_sensitive = result.get('is_sensitive', False)

            # CORRECTION :
            # La preuve de collecte appartient au cookie analysé.
            proof = cookie.get('proof', {})

            sensitive_tag = " **[SENSIBLE]**" if is_sensitive else ""
            content += f"### {cookie.get('name', 'N/A')}{sensitive_tag} ({risk})\n\n"

            content += "**Attributs :**\n"
            for key, value in (cookie.get('attributes') or {}).items():
                content += f"- **{key}**: {value}\n"

            if 'value_length' in cookie or cookie.get('value_sha256'):
                content += "\n**Metadonnees de valeur :**\n"
                if 'value_length' in cookie:
                    content += f"- Longueur: {cookie.get('value_length')}\n"
                if cookie.get('value_sha256'):
                    content += f"- SHA-256: `{cookie.get('value_sha256')}`\n"

            if proof:
                content += "\n**Preuve de collecte :**\n"
                content += f"- Source: {proof.get('source_url', 'N/A')}\n"
                content += f"- Timestamp: {proof.get('timestamp', 'N/A')}\n"
                if proof.get('raw_header'):
                    content += f"- En-tete brut: `{proof.get('raw_header', '')}`\n"

            issues = result.get('issues', [])
            if issues:
                content += "\n**Problemes detectes :**\n\n"
                for issue in issues:
                    content += f"- **{issue.get('name', '')}** ({issue.get('risk', '')})\n"
                    content += f"  - {issue.get('description', '')}\n"
                    content += f"  - {issue.get('recommendation', '')}\n"
            else:
                content += "\nCe cookie est conforme.\n"

            content += "\n---\n\n"

        filepath = os.path.join(self.output_dir, f"{base_filename}.md")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return filepath
