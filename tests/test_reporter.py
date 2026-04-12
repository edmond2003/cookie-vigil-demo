#!/usr/bin/env python3
"""
Tests unitaires pour le module reporter.py
Teste la génération des rapports
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import json
import tempfile
import shutil
from src.reporter import CookieReporter

class TestReporter(unittest.TestCase):
    """Test du générateur de rapports"""
    
    def setUp(self):
        """Créer un dossier temporaire pour les tests"""
        self.test_dir = tempfile.mkdtemp()
        self.reporter = CookieReporter(output_dir=self.test_dir)
        
        # Données de test
        self.test_analysis = {
            'results': [
                {
                    'cookie': {'name': 'session', 'attributes': {'secure': True}},
                    'issues': [],
                    'risk_level': 'INFO',
                    'is_secure': True
                },
                {
                    'cookie': {'name': 'bad', 'attributes': {'secure': False}},
                    'issues': [
                        {'id': 'SECURE_MISSING', 'name': 'Secure manquant', 'risk': 'CRITICAL'}
                    ],
                    'risk_level': 'CRITICAL',
                    'is_secure': False
                }
            ],
            'statistics': {
                'total': 2,
                'secure_count': 1,
                'insecure_count': 1,
                'risk_counts': {'CRITICAL': 1, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 1}
            }
        }
    
    def tearDown(self):
        """Nettoyer le dossier temporaire"""
        shutil.rmtree(self.test_dir)
    
    def test_generate_json_report(self):
        """Test: Génération rapport JSON"""
        filepath = self.reporter.generate_report(self.test_analysis, 'json', 'test')
        
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.json'))
        
        # Vérifier le contenu JSON
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.assertIn('statistics', data)
            self.assertIn('cookies', data)
        
        print("  ✅ Rapport JSON généré OK")
    
    def test_generate_html_report(self):
        """Test: Génération rapport HTML"""
        filepath = self.reporter.generate_report(self.test_analysis, 'html', 'test')
        
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.html'))
        
        # Vérifier que le fichier contient du HTML
        with open(filepath, 'r') as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('Rapport', content)
        
        print("  ✅ Rapport HTML généré OK")
    
    def test_generate_csv_report(self):
        """Test: Génération rapport CSV"""
        filepath = self.reporter.generate_report(self.test_analysis, 'csv', 'test')
        
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.csv'))
        
        # Vérifier le contenu CSV
        with open(filepath, 'r') as f:
            content = f.read()
            self.assertIn('Cookie,Risque', content)
        
        print("  ✅ Rapport CSV généré OK")
    
    def test_generate_markdown_report(self):
        """Test: Génération rapport Markdown"""
        filepath = self.reporter.generate_report(self.test_analysis, 'md', 'test')
        
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.md'))
        
        # Vérifier le contenu Markdown
        with open(filepath, 'r') as f:
            content = f.read()
            self.assertIn('# Rapport', content)
        
        print("  ✅ Rapport Markdown généré OK")
    
    def test_all_formats_generation(self):
        """Test: Génération de tous les formats"""
        formats = ['json', 'html', 'csv', 'md']
        for fmt in formats:
            filepath = self.reporter.generate_report(self.test_analysis, fmt, f'test_{fmt}')
            self.assertTrue(os.path.exists(filepath))
        
        print("  ✅ Tous les formats générés OK")
    
    def test_report_contains_expected_data(self):
        """Test: Le rapport contient les données attendues"""
        filepath = self.reporter.generate_report(self.test_analysis, 'json', 'test_data')
        
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.assertEqual(data['statistics']['total'], 2)
            self.assertEqual(data['statistics']['secure_count'], 1)
        
        print("  ✅ Données du rapport correctes")

def run_all_tests():
    """Exécute tous les tests"""
    print("\n" + "="*60)
    print("🧪 TESTS UNITAIRES - MODULE REPORTER")
    print("="*60 + "\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestReporter)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("📊 RÉSULTAT DES TESTS REPORTER")
    print("="*60)
    print(f"✅ Tests passés: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
EOF
