#!/usr/bin/env python3
"""Tests unitaires pour le module reporter.py"""

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
                    'cookie': {'name': 'session', 'attributes': {'secure': True}},
                    'issues': [],
                    'risk_level': 'INFO',
                    'is_sensitive': False
                },
                {
                    'cookie': {'name': 'bad', 'attributes': {'secure': False}},
                    'issues': [{'id': 'SECURE_MISSING', 'name': 'Secure manquant', 'risk': 'CRITICAL'}],
                    'risk_level': 'CRITICAL',
                    'is_sensitive': True
                }
            ],
            'statistics': {
                'total': 2, 'secure_count': 1, 'insecure_count': 1, 'sensitive_count': 1,
                'risk_counts': {'CRITICAL': 1, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 1}
            }
        }
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_generate_json(self):
        filepath = self.reporter.generate_report(self.test_data, 'json', 'test')
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            data = json.load(f)
            self.assertEqual(data['statistics']['total'], 2)
    
    def test_generate_html(self):
        filepath = self.reporter.generate_report(self.test_data, 'html', 'test')
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('session', content)
    
    def test_generate_csv(self):
        filepath = self.reporter.generate_report(self.test_data, 'csv', 'test')
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            content = f.read()
            self.assertIn('session', content)
            self.assertIn('Sensible', content)
    
    def test_generate_markdown(self):
        filepath = self.reporter.generate_report(self.test_data, 'md', 'test')
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            content = f.read()
            self.assertIn('# Rapport', content)
    
    # === Tests d'erreurs (NOUVEAU) ===
    def test_generate_report_empty_data(self):
        """Test: Génération avec données vides → erreur"""
        with self.assertRaises(ValueError):
            self.reporter.generate_report({}, 'html')
    
    def test_generate_report_invalid_format(self):
        """Test: Format invalide → erreur"""
        with self.assertRaises(ValueError):
            self.reporter.generate_report(self.test_data, 'invalid_format')


if __name__ == "__main__":
    unittest.main()
