#!/usr/bin/env python3
"""Tests d'intégration - collector, analyzer et reporter ensemble."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import tempfile
import shutil
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
        shutil.rmtree(self.test_dir)

    def test_full_pipeline_with_session_cookie(self):
        mock_cookies = [
            {
                'name': 'session_token',
                'value': 'abc123',
                'raw_value_for_analysis': 'abc123',
                'value_length': 6,
                'attributes': {'secure': False, 'httponly': False, 'samesite': None, 'path': '/'}
            }
        ]

        analysis = self.analyzer.analyze_cookies(
            mock_cookies,
            {'is_https': True, 'force_check': False},
            source_url='https://test.com'
        )

        self.assertEqual(analysis['statistics']['total'], 1)
        self.assertEqual(analysis['results'][0]['category'], 'SESSION')
        self.assertEqual(analysis['results'][0]['risk_level'], 'CRITICAL')
        self.assertGreater(len(analysis['results'][0]['correlations']), 0)

        filepath = self.reporter.generate_report(analysis, 'json', 'integration_test')
        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertEqual(data['cookies'][0]['category'], 'SESSION')

    def test_pipeline_empty_cookies(self):
        analysis = self.analyzer.analyze_cookies([], {'is_https': True, 'force_check': False})

        self.assertEqual(analysis['statistics']['total'], 0)
        self.assertEqual(analysis['statistics']['secure_count'], 0)
        self.assertEqual(analysis['statistics']['insecure_count'], 0)
        self.assertEqual(len(analysis['results']), 0)

    def test_analyzer_with_collector_output_structure(self):
        cookie_from_collector = {
            'name': 'tracking_id',
            'value': 'track_123',
            'raw_value_for_analysis': 'track_123',
            'value_length': 9,
            'value_sha256': 'fakehash',
            'attributes': {
                'domain': '.example.com',
                'path': '/',
                'secure': False,
                'httponly': False,
                'samesite': None
            },
            'proof': {
                'source_url': 'https://test.com',
                'timestamp': '2026-05-19T12:00:00',
                'response_status': 200,
                'tls_verified': True,
                'raw_header': 'tracking_id=track_123; Path=/'
            }
        }

        result = self.analyzer.analyze_cookie(cookie_from_collector, {'is_https': True, 'force_check': False})

        self.assertIn('risk_level', result)
        self.assertIn('issues', result)
        self.assertIn('is_sensitive', result)
        self.assertIn('category', result)
        self.assertEqual(result['category'], 'TRACKING')
        self.assertEqual(result['risk_level'], 'LOW')

    def test_all_rules_loaded(self):
        self.assertEqual(len(self.analyzer.RULES), 11)

        rule_ids = [r['id'] for r in self.analyzer.RULES]
        expected = [
            'SECURE_MISSING',
            'HTTPONLY_MISSING',
            'SAMESITE_MISSING',
            'SAMESITE_NONE_INSECURE',
            'DOMAIN_TOO_BROAD',
            'PATH_TOO_BROAD',
            'EXPIRES_LONG',
            'PREFIX_SECURE_MISSING',
            'PREFIX_HOST_MISSING',
            'WEAK_TOKEN',
            'JWT_DETECTED'
        ]

        for rule in expected:
            self.assertIn(rule, rule_ids)

    def test_sensitive_cookie_propagation(self):
        cookie = {
            'name': 'session_token',
            'value': 'a' * 32,
            'attributes': {'secure': False, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }

        result = self.analyzer.analyze_cookie(cookie, {'is_https': True, 'force_check': False})

        self.assertTrue(result.get('is_sensitive', False))
        self.assertEqual(result.get('category'), 'SESSION')
        self.assertEqual(result.get('risk_level'), 'CRITICAL')

    def test_report_generation_with_category_counts(self):
        cookies = [
            {
                'name': 'session_token',
                'value': 'a' * 32,
                'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/'}
            },
            {
                'name': 'theme',
                'value': 'dark',
                'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
            }
        ]

        analysis = self.analyzer.analyze_cookies(cookies, {'is_https': True, 'force_check': False})
        filepath = self.reporter.generate_report(analysis, 'json', 'category_report')

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertIn('category_counts', data['statistics'])
        self.assertEqual(data['statistics']['category_counts']['SESSION'], 1)
        self.assertEqual(data['statistics']['category_counts']['FUNCTIONAL'], 1)


if __name__ == "__main__":
    unittest.main()
