import json
import csv
from datetime import datetime
from typing import Dict, List, Any
import os
from jinja2 import Template

class CookieReporter:
    """
    Générateur de rapports d'analyse de cookies.
    Supporte plusieurs formats (JSON, CSV, HTML, Markdown).
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialise le générateur de rapports.
        
        Args:
            output_dir: Répertoire de sortie des rapports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Template HTML pour les rapports
        self.html_template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'analyse des cookies - {{ timestamp }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .summary { background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .cookie-card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .risk-CRITICAL { border-left: 5px solid #dc3545; background: #fff5f5; }
        .risk-HIGH { border-left: 5px solid #fd7e14; background: #fff3e0; }
        .risk-MEDIUM { border-left: 5px solid #ffc107; background: #fff9e6; }
        .risk-LOW { border-left: 5px solid #28a745; background: #f0fff4; }
        .risk-INFO { border-left: 5px solid #17a2b8; background: #e3f2fd; }
        .issue { margin: 10px 0; padding: 10px; background: white; border-radius: 3px; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }
        .badge.CRITICAL { background: #dc3545; }
        .badge.HIGH { background: #fd7e14; }
        .badge.MEDIUM { background: #ffc107; color: #333; }
        .badge.LOW { background: #28a745; }
        .badge.INFO { background: #17a2b8; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍪 Rapport d'analyse de sécurité des cookies</h1>
        <p><strong>Date :</strong> {{ timestamp }}</p>
        
        <div class="summary">
            <h2>Résumé</h2>
            <table>
                <tr><th>Total cookies analysés</th><td>{{ stats.total }}</td></tr>
                <tr><th>Cookies sécurisés</th><td>{{ stats.secure_count }}</td></tr>
                <tr><th>Cookies non sécurisés</th><td>{{ stats.insecure_count }}</td></tr>
            </table>
            
            <h3>Répartition par risque</h3>
            <table>
                {% for level, count in stats.risk_counts.items() %}
                <tr>
                    <td><span class="badge {{ level }}">{{ level }}</span></td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        <h2>Détail des cookies</h2>
        {% for result in results %}
        <div class="cookie-card risk-{{ result.risk_level }}">
            <h3>🍪 {{ result.cookie.name }}</h3>
            <p><strong>Niveau de risque :</strong> <span class="badge {{ result.risk_level }}">{{ result.risk_level }}</span></p>
            <p><strong>Attributs :</strong></p>
            <table>
                {% for key, value in result.cookie.attributes.items() %}
                <tr><th>{{ key }}</th><td>{{ value }}</td></tr>
                {% endfor %}
            </table>
            
            <h4>Problèmes détectés :</h4>
            {% for issue in result.issues %}
            <div class="issue">
                <p><strong>⚠️ {{ issue.name }}</strong> ({{ issue.risk }})</p>
                <p>{{ issue.description }}</p>
                <p><em>💡 Recommandation :</em> {{ issue.recommendation }}</p>
            </div>
            {% endfor %}
            
            {% if result.is_secure %}
            <p style="color: green;">✅ Ce cookie semble bien configuré</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """)
    
    def generate_report(self, analysis_result: Dict, format: str = "json", filename: str = None) -> str:
        """
        Génère un rapport dans le format spécifié.
        
        Args:
            analysis_result: Résultat de l'analyse
            format: Format du rapport (json, csv, html, md)
            filename: Nom du fichier (optionnel)
            
        Returns:
            Chemin du fichier généré
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not filename:
            filename = f"cookie_audit_{timestamp}"
        
        if format == "json":
            return self._generate_json(analysis_result, filename, timestamp)
        elif format == "html":
            return self._generate_html(analysis_result, filename, timestamp)
        elif format == "csv":
            return self._generate_csv(analysis_result, filename, timestamp)
        elif format == "md":
            return self._generate_markdown(analysis_result, filename, timestamp)
        else:
            raise ValueError(f"Format non supporté: {format}")
    
    def _generate_json(self, analysis_result: Dict, filename: str, timestamp: str) -> str:
        """Génère un rapport JSON."""
        output = {
            'timestamp': timestamp,
            'statistics': analysis_result['statistics'],
            'cookies': analysis_result['results']
        }
        
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _generate_html(self, analysis_result: Dict, filename: str, timestamp: str) -> str:
        """Génère un rapport HTML."""
        html_content = self.html_template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats=analysis_result['statistics'],
            results=analysis_result['results']
        )
        
        filepath = os.path.join(self.output_dir, f"{filename}.html")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_csv(self, analysis_result: Dict, filename: str, timestamp: str) -> str:
        """Génère un rapport CSV."""
        filepath = os.path.join(self.output_dir, f"{filename}.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Cookie', 'Risque', 'Problèmes', 'Recommandations', 'Secure', 'HttpOnly', 'SameSite'])
            
            for result in analysis_result['results']:
                cookie = result['cookie']
                attrs = cookie.get('attributes', {})
                
                issues = '; '.join([i['name'] for i in result['issues']])
                recommendations = '; '.join([i['recommendation'] for i in result['issues']])
                
                writer.writerow([
                    cookie['name'],
                    result['risk_level'],
                    issues,
                    recommendations,
                    attrs.get('secure', False),
                    attrs.get('httponly', False),
                    attrs.get('samesite', '')
                ])
        
        return filepath
    
    def _generate_markdown(self, analysis_result: Dict, filename: str, timestamp: str) -> str:
        """Génère un rapport Markdown."""
        content = f"# Rapport d'analyse des cookies\n\n"
        content += f"**Date :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        content += "## Résumé\n\n"
        stats = analysis_result['statistics']
        content += f"- **Total cookies :** {stats['total']}\n"
        content += f"- **Cookies sécurisés :** {stats['secure_count']}\n"
        content += f"- **Cookies non sécurisés :** {stats['insecure_count']}\n\n"
        
        content += "### Répartition par risque\n\n"
        for level, count in stats['risk_counts'].items():
            content += f"- **{level} :** {count}\n"
        
        content += "\n## Détail des cookies\n\n"
        
        for result in analysis_result['results']:
            cookie = result['cookie']
            content += f"### 🍪 {cookie['name']} ({result['risk_level']})\n\n"
            
            content += "**Attributs :**\n\n"
            for key, value in cookie.get('attributes', {}).items():
                content += f"- {key}: {value}\n"
            
            if result['issues']:
                content += "\n**Problèmes détectés :**\n\n"
                for issue in result['issues']:
                    content += f"- ⚠️ **{issue['name']}** ({issue['risk']})\n"
                    content += f"  - {issue['description']}\n"
                    content += f"  - 💡 *{issue['recommendation']}*\n"
            else:
                content += "\n✅ Cookie bien configuré.\n"
            
            content += "\n---\n\n"
        
        filepath = os.path.join(self.output_dir, f"{filename}.md")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return filepath
