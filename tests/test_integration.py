#!/usr/bin/env python3
"""Tests d'intégration - Tous les modules ensemble"""

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
    
    def setUp(self):
        self.collector = CookieCollector(timeout=5, verify_ssl=False)
        self.analyzer = CookieAnalyzer()
        self.test_dir = tempfile.mkdtemp()
        self.reporter = CookieReporter(output_dir=self.test_dir)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_full_pipeline_with_mock_data(self):
        mock_cookies = [
            {
                'name': 'session',
                'value': 'abc123',
                'attributes': {'secure': False, 'httponly': False, 'samesite': None}
            }
        ]
        
        context = {'is_https': True}
        analysis = self.analyzer.analyze_cookies(mock_cookies, context, source_url='https://test.com')
        
        self.assertEqual(analysis['statistics']['total'], 1)
        self.assertGreater(analysis['statistics']['insecure_count'], 0)
        
        filepath = self.reporter.generate_report(analysis, 'json', 'integration_test')
        self.assertTrue(os.path.exists(filepath))
    
    def test_pipeline_empty_cookies(self):
        """Test: Pipeline avec liste de cookies vide (NOUVEAU)"""
        analysis = self.analyzer.analyze_cookies([], {'is_https': True})
        self.assertEqual(analysis['statistics']['total'], 0)
        self.assertEqual(analysis['statistics']['secure_count'], 0)
        self.assertEqual(analysis['statistics']['insecure_count'], 0)
        self.assertEqual(len(analysis['results']), 0)
    
    def test_analyzer_with_collector_output_structure(self):
        cookie_from_collector = {
            'name': 'test_cookie',
            'value': 'test_value',
            'attributes': {
                'domain': '.example.com',
                'path': '/',
                'secure': False,
                'httponly': False,
                'samesite': None
            }
        }
        
        result = self.analyzer.analyze_cookie(cookie_from_collector, {'is_https': True})
        
        self.assertIn('risk_level', result)
        self.assertIn('issues', result)
        self.assertIn('is_sensitive', result)
    
    def test_all_owasp_rules_loaded(self):
        self.assertEqual(len(self.analyzer.RULES), 9)
        rule_ids = [r['id'] for r in self.analyzer.RULES]
        expected = ['SECURE_MISSING', 'HTTPONLY_MISSING', 'SAMESITE_MISSING',
                    'SAMESITE_NONE_INSECURE', 'DOMAIN_TOO_BROAD', 'PATH_TOO_BROAD',
                    'EXPIRES_LONG', 'PREFIX_SECURE_MISSING', 'PREFIX_HOST_MISSING']
        for rule in expected:
            self.assertIn(rule, rule_ids)
    
    def test_sensitive_cookie_propagation(self):
        cookie = {'name': 'session_token', 'attributes': {'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, {'is_https': True})
        self.assertTrue(result.get('is_sensitive', False))


if __name__ == "__main__":
    unittest.main()
