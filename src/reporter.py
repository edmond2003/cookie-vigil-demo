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

        # Template HTML avec échappement complet (CORRIGÉ)
        self.html_template = Template("""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport CookieSentinel - {{ timestamp }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
        .container { max-width: 1300px; margin: auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; }
        .summary { background: #e8f4f8; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .cookie-card { 
            border: 1px solid #ddd; 
            padding: 18px; 
            margin: 15px 0; 
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
        }
        .risk-CRITICAL { border-left: 6px solid #dc3545; background: #fff5f5; }
        .risk-HIGH { border-left: 6px solid #fd7e14; background: #fff3e0; }
        .risk-MEDIUM { border-left: 6px solid #ffc107; background: #fff9e6; }
        .risk-LOW, .risk-INFO { border-left: 6px solid #28a745; background: #f0fff4; }
        .badge { 
            display: inline-block; 
            padding: 4px 10px; 
            border-radius: 4px; 
            color: white; 
            font-weight: bold;
        }
        .badge.CRITICAL { background: #dc3545; }
        .badge.HIGH { background: #fd7e14; }
        .badge.MEDIUM { background: #ffc107; color: #333; }
        .badge.LOW, .badge.INFO { background: #28a745; }
        .sensitive-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            background: #ff9800;
            color: white;
            font-size: 12px;
            margin-left: 10px;
        }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
        .issue { background: #fff; padding: 12px; margin: 8px 0; border-left: 4px solid #ffc107; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍪 Rapport d'analyse de sécurité des cookies</h1>
        <p><strong>Généré le :</strong> {{ timestamp }}</p>
        
        <div class="summary">
            <h2>Résumé Global</h2>
            <table>
                <tr><th>Total cookies analysés</th><td>{{ stats.total }}</td></tr>
                <tr><th>Cookies sécurisés</th><td>{{ stats.secure_count }}</td></tr>
                <tr><th>Cookies non sécurisés</th><td>{{ stats.insecure_count }}</td></tr>
                {% if stats.sensitive_count %}
                <tr style="background: #fff3e0;">
                    <th>🔐 Cookies SENSIBLES détectés</th>
                    <td><strong style="color: #ff9800;">{{ stats.sensitive_count }}</strong></strong></td>
                </tr>
                {% endif %}
            </table>
            
            <h3>Répartition par niveau de risque</h3>
            <table>
                {% for level, count in stats.risk_counts.items() %}
                <tr>
                    <td><span class="badge {{ level }}">{{ level }}</span></span></td>
                    <td><strong>{{ count }}</strong></strong></td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <h2>Détails des cookies analysés</h2>
        {% for result in results %}
        <div class="cookie-card risk-{{ result.risk_level }}">
            <h3>
                🍪 {{ result.cookie.name | e }}
                {% if result.is_sensitive %}
                <span class="sensitive-badge">🔐 SENSIBLE</span>
                {% endif %}
            </h3>
            <p><strong>Niveau de risque :</strong> <span class="badge {{ result.risk_level }}">{{ result.risk_level }}</span></p>
            
            <h4>Attributs du cookie</h4>
            <table>
                {% for key, value in (result.cookie.attributes or {}).items() %}
                <tr><th>{{ key | e }}</th><td>{{ value | default('Non défini') | e }}</td>
                {% endfor %}
            </table>
            
            {% if result.issues %}
            <h4>Problèmes détectés ({{ result.issues|length }})</h4>
            {% for issue in result.issues %}
            <div class="issue">
                <p><strong>⚠️ {{ issue.name | e }}</strong> ({{ issue.risk }})</p>
                <p>{{ issue.description | e }}</p>
                <p><strong>Recommandation :</strong> {{ issue.recommendation | e }}</p>
            </div>
            {% endfor %}
            {% else %}
            <p style="color: #28a745; font-weight: bold;">✅ Ce cookie est bien configuré selon OWASP</p>
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
            writer.writerow(['URL', 'Cookie', 'Sensible', 'Risque', 'Problèmes', 'Recommandations',
                             'Secure', 'HttpOnly', 'SameSite', 'Domain', 'Path'])
            
            for result in results:
                cookie = result.get('cookie', {})
                attrs = cookie.get('attributes', {}) or {}
                issues = result.get('issues', [])
                
                writer.writerow([
                    result.get('final_url', 'N/A'),
                    cookie.get('name', 'N/A'),
                    '✅ OUI' if result.get('is_sensitive', False) else '❌ NON',
                    result.get('risk_level', 'INFO'),
                    '; '.join(i.get('name', '') for i in issues),
                    '; '.join(i.get('recommendation', '') for i in issues),
                    attrs.get('secure', False),
                    attrs.get('httponly', False),
                    attrs.get('samesite', ''),
                    attrs.get('domain', ''),
                    attrs.get('path', '/')
                ])
        return filepath

    def _generate_markdown(self, stats: Dict, results: List, base_filename: str, timestamp: str) -> str:
        content = "# Rapport d'analyse de sécurité des cookies\n\n"
        content += f"**Généré le :** {timestamp}\n\n"
        
        content += "## Résumé\n\n"
        content += f"- **Total cookies :** {stats.get('total', 0)}\n"
        content += f"- **Cookies sécurisés :** {stats.get('secure_count', 0)}\n"
        content += f"- **Cookies non sécurisés :** {stats.get('insecure_count', 0)}\n"
        
        sensitive_count = stats.get('sensitive_count', 0)
        if sensitive_count > 0:
            content += f"- **🔐 Cookies SENSIBLES :** {sensitive_count}\n"
        
        content += "\n### Répartition par risque\n\n"
        for level, count in stats.get('risk_counts', {}).items():
            content += f"- **{level}**: {count} cookies\n"
        
        content += "\n## Détails des cookies\n\n"
        
        for result in results:
            cookie = result.get('cookie', {})
            risk = result.get('risk_level', 'INFO')
            is_sensitive = result.get('is_sensitive', False)
            
            sensitive_tag = " 🔐 **[SENSIBLE]**" if is_sensitive else ""
            content += f"### 🍪 {cookie.get('name', 'N/A')}{sensitive_tag} ({risk})\n\n"
            
            content += "**Attributs :**\n"
            for key, value in (cookie.get('attributes') or {}).items():
                content += f"- **{key}**: {value}\n"
            
            issues = result.get('issues', [])
            if issues:
                content += "\n**Problèmes détectés :**\n\n"
                for issue in issues:
                    content += f"- **{issue.get('name', '')}** ({issue.get('risk', '')})\n"
                    content += f"  - {issue.get('description', '')}\n"
                    content += f"  - 💡 {issue.get('recommendation', '')}\n"
            else:
                content += "\n✅ Ce cookie est conforme.\n"
            
            content += "\n---\n\n"
        
        filepath = os.path.join(self.output_dir, f"{base_filename}.md")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return filepath
