#!/usr/bin/env python3
"""Tests unitaires pour reporter.py - JSON, HTML, CSV, Markdown."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import tempfile
import shutil
import json
from src.reporter import CookieReporter


class TestReporter(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.reporter = CookieReporter(output_dir=self.test_dir)

        self.test_data = {
            'results': [
                {
                    'cookie': {
                        'name': 'session_token',
                        'value': 'abc123',
                        'value_length': 6,
                        'value_sha256': 'fakehash',
                        'attributes': {'secure': False, 'httponly': False, 'samesite': None},
                        'proof': {
                            'source_url': 'https://test.com/login',
                            'timestamp': '2026-05-19T12:00:00',
                            'response_status': 200,
                            'tls_verified': True,
                            'raw_header': 'session_token=abc123; Path=/'
                        }
                    },
                    'issues': [{
                        'id': 'SECURE_MISSING',
                        'name': 'Attribut Secure manquant',
                        'description': 'Le cookie peut être transmis sur une connexion non chiffrée',
                        'risk': 'CRITICAL',
                        'recommendation': 'Ajouter Secure'
                    }],
                    'correlations': [{
                        'id': 'SESSION_EXPOSURE_COMBINED',
                        'title': 'Cookie de session exposé',
                        'risk': 'CRITICAL',
                        'impact': 'Vol de session',
                        'recommendation': 'Ajouter Secure et HttpOnly'
                    }],
                    'risk_level': 'CRITICAL',
                    'is_sensitive': True,
                    'category': 'SESSION',
                    'final_url': 'https://test.com/login'
                },
                {
                    'cookie': {
                        'name': 'theme',
                        'value': 'dark',
                        'value_length': 4,
                        'value_sha256': 'fakehash2',
                        'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax'}
                    },
                    'issues': [],
                    'correlations': [],
                    'risk_level': 'INFO',
                    'is_sensitive': False,
                    'category': 'FUNCTIONAL',
                    'final_url': 'https://test.com/theme'
                }
            ],
            'statistics': {
                'total': 2,
                'secure_count': 1,
                'insecure_count': 1,
                'sensitive_count': 1,
                'security_score': 82,
                'risk_counts': {
                    'CRITICAL': 1,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 1
                },
                'category_counts': {
                    'SESSION': 1,
                    'FUNCTIONAL': 1
                }
            }
        }

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_generate_json(self):
        filepath = self.reporter.generate_report(self.test_data, 'json', 'test_json')
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.json'))

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertEqual(data['statistics']['total'], 2)
        self.assertEqual(data['statistics']['security_score'], 82)
        self.assertEqual(data['cookies'][0]['category'], 'SESSION')
        self.assertEqual(data['cookies'][0]['correlations'][0]['id'], 'SESSION_EXPOSURE_COMBINED')

    def test_generate_html(self):
        filepath = self.reporter.generate_report(self.test_data, 'html', 'test_html')
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.html'))

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn('<!DOCTYPE html>', content)
        self.assertIn('CookieVigil', content)
        self.assertIn('session_token', content)
        self.assertIn('theme', content)
        self.assertIn('Preuve de collecte', content)
        self.assertIn('fakehash', content)

    def test_generate_csv(self):
        filepath = self.reporter.generate_report(self.test_data, 'csv', 'test_csv')
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.csv'))

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn('session_token', content)
        self.assertIn('theme', content)
        self.assertIn('Sensible', content)
        self.assertIn('Value_Length', content)
        self.assertIn('Value_SHA256', content)
        self.assertIn('CRITICAL', content)

    def test_generate_markdown(self):
        filepath = self.reporter.generate_report(self.test_data, 'md', 'test_md')
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith('.md'))

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn('CookieVigil', content)
        self.assertIn('session_token', content)
        self.assertIn('theme', content)
        self.assertIn('CRITICAL', content)
        self.assertIn('SHA-256', content)
        self.assertIn('Preuve de collecte', content)

    def test_generate_report_empty_data(self):
        with self.assertRaises(ValueError):
            self.reporter.generate_report({}, 'html')

        with self.assertRaises(ValueError):
            self.reporter.generate_report(None, 'html')

    def test_generate_report_invalid_format(self):
        with self.assertRaises(ValueError):
            self.reporter.generate_report(self.test_data, 'invalid_format')

    def test_all_formats_generation(self):
        for fmt in ['json', 'html', 'csv', 'md']:
            filepath = self.reporter.generate_report(self.test_data, fmt, f'test_all_{fmt}')
            self.assertTrue(os.path.exists(filepath))


if __name__ == "__main__":
    unittest.main()
