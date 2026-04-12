#!/usr/bin/env python3
"""
Tests d'intégration - Vérifie que tous les modules fonctionnent ensemble
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import tempfile
import json
from src.collector import CookieCollector
from src.analyzer import CookieAnalyzer
from src.reporter import CookieReporter

class TestIntegration(unittest.TestCase):
    """Test que tous les modules fonctionnent ensemble"""
    
    def setUp(self):
        self.collector = CookieCollector(timeout=10)
        self.analyzer = CookieAnalyzer()
        self.test_dir = tempfile.mkdtemp()
        self.reporter = CookieReporter(output_dir=self.test_dir)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_collector_to_analyzer_flow(self):
        """Test: Flux Collector → Analyzer (avec données mockées)"""
        from unittest.mock import patch, MagicMock
        
        # Simuler une réponse HTTP
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://test.com"
        mock_response.history = []
        
        mock_raw = MagicMock()
        mock_raw.headers.getlist.return_value = [
            'session=abc123; Secure; HttpOnly; SameSite=Lax'
        ]
        mock_response.raw = mock_raw
        
        with patch('src.collector.requests.Session.get', return_value=mock_response):
            # 1. Collecte
            collected = self.collector.collect_from_url("https://test.com")
            self.assertNotIn('error', collected)
            self.assertEqual(len(collected['cookies']), 1)
            
            # 2. Analyse
            analysis = self.analyzer.analyze_cookies(
                collected['cookies'], 
                {'is_https': True}
            )
            
            # 3. Vérifications
            self.assertEqual(analysis['statistics']['total'], 1)
            # Cookie bien configuré
            self.assertTrue(analysis['results'][0]['is_secure'])
        
        print("  ✅ Flux Collector → Analyzer OK")
    
    def test_analyzer_to_reporter_flow(self):
        """Test: Flux Analyzer → Reporter"""
        # Créer des données d'analyse
        test_cookies = [
            {'name': 'secure', 'attributes': {'secure': True, 'httponly': True}}
        ]
        
        analysis = self.analyzer.analyze_cookies(test_cookies, {'is_https': True})
        
        # Générer rapport
        filepath = self.reporter.generate_report(analysis, 'json', 'integration_test')
        
        # Vérifier
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.assertEqual(data['statistics']['total'], 1)
        
        print("  ✅ Flux Analyzer → Reporter OK")
    
    def test_full_pipeline_with_mock_data(self):
        """Test: Pipeline complet Collector → Analyzer → Reporter"""
        from unittest.mock import patch, MagicMock
        
        # Simuler une réponse avec cookies problématiques
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://test.com"
        mock_response.history = []
        
        mock_raw = MagicMock()
        mock_raw.headers.getlist.return_value = [
            'session=abc; Secure; HttpOnly',
            'tracking=xyz; Domain=.test.com'
        ]
        mock_response.raw = mock_raw
        
        with patch('src.collector.requests.Session.get', return_value=mock_response):
            # 1. Collecte
            collected = self.collector.collect_from_url("https://test.com")
            
            # 2. Analyse
            analysis = self.analyzer.analyze_cookies(
                collected['cookies'],
                {'is_https': True}
            )
            
            # 3. Rapport
            filepath = self.reporter.generate_report(analysis, 'html', 'full_pipeline')
            
            # 4. Vérifications
            self.assertTrue(os.path.exists(filepath))
            self.assertEqual(analysis['statistics']['total'], 2)
            self.assertGreater(analysis['statistics']['insecure_count'], 0)
        
        print("  ✅ Pipeline complet OK")
    
    def test_error_handling_in_pipeline(self):
        """Test: Gestion des erreurs dans le pipeline"""
        # URL invalide
        collected = self.collector.collect_from_url("https://unreachable-site-12345.com")
        
        self.assertIn('error', collected)
        
        # Même avec erreur, l'analyse doit gérer le cas
        if collected.get('cookies'):
            analysis = self.analyzer.analyze_cookies(collected['cookies'], {'is_https': True})
            self.assertIsNotNone(analysis)
        
        print("  ✅ Gestion d'erreur OK")
    
    def test_multiple_urls_analysis(self):
        """Test: Analyse de plusieurs URLs"""
        from unittest.mock import patch, MagicMock
        
        def mock_request(url, **kwargs):
            mock = MagicMock()
            mock.status_code = 200
            mock.url = url
            mock.history = []
            mock_raw = MagicMock()
            if 'google' in url:
                mock_raw.headers.getlist.return_value = ['cookie_google=abc; Secure']
            else:
                mock_raw.headers.getlist.return_value = ['cookie_other=xyz']
            mock.raw = mock_raw
            return mock
        
        with patch('src.collector.requests.Session.get', side_effect=mock_request):
            urls = ["https://google.com", "https://example.com"]
            results = []
            
            for url in urls:
                collected = self.collector.collect_from_url(url)
                analysis = self.analyzer.analyze_cookies(
                    collected.get('cookies', []),
                    {'is_https': True}
                )
                results.append(analysis)
            
            self.assertEqual(len(results), 2)
        
        print("  ✅ Multi-URLs OK")

def run_all_tests():
    """Exécute tous les tests d'intégration"""
    print("\n" + "="*60)
    print("🧪 TESTS D'INTÉGRATION - TOUS LES MODULES ENSEMBLE")
    print("="*60 + "\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIntegration)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("📊 RÉSULTAT DES TESTS D'INTÉGRATION")
    print("="*60)
    print(f"✅ Tests passés: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
EOF
