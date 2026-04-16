#!/usr/bin/env python3
"""Tests unitaires pour le module analyzer.py (9 règles OWASP)"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.analyzer import CookieAnalyzer


class TestAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.analyzer = CookieAnalyzer()
        self.ctx_https = {'is_https': True}
        self.ctx_http = {'is_https': False}
    
    # === Règle 1: SECURE_MISSING ===
    def test_secure_missing_critical(self):
        cookie = {'name': 'test', 'attributes': {'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'SECURE_MISSING']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'CRITICAL')
    
    # === Règle 2: HTTPONLY_MISSING ===
    def test_httponly_missing_high(self):
        cookie = {'name': 'test', 'attributes': {'httponly': False}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'HTTPONLY_MISSING']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'HIGH')
    
    # === Règle 3: SAMESITE_MISSING ===
    def test_samesite_missing_medium(self):
        cookie = {'name': 'test', 'attributes': {}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'SAMESITE_MISSING']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'MEDIUM')
    
    # === Règle 4: SAMESITE_NONE_INSECURE ===
    def test_samesite_none_insecure_critical(self):
        cookie = {'name': 'test', 'attributes': {'samesite': 'None', 'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'SAMESITE_NONE_INSECURE']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'CRITICAL')
    
    # === Règle 5: DOMAIN_TOO_BROAD ===
    def test_domain_too_broad_medium(self):
        cookie = {'name': 'test', 'attributes': {'domain': '.example.com'}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'DOMAIN_TOO_BROAD']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'MEDIUM')
    
    # === Règle 6: PATH_TOO_BROAD ===
    def test_path_too_broad_low(self):
        cookie = {'name': 'test', 'attributes': {'path': '/'}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'PATH_TOO_BROAD']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'LOW')
    
    # === Règle 7: PREFIX_SECURE_MISSING ===
    def test_secure_prefix_missing_high(self):
        cookie = {'name': '__Secure-test', 'attributes': {'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'PREFIX_SECURE_MISSING']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'HIGH')
    
    # === Règle 8: PREFIX_HOST_MISSING ===
    def test_host_prefix_missing_high(self):
        cookie = {'name': '__Host-test', 'attributes': {'secure': False, 'domain': 'example.com'}}
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issues = [i for i in result['issues'] if i['id'] == 'PREFIX_HOST_MISSING']
        self.assertTrue(issues)
        self.assertEqual(issues[0]['risk'], 'HIGH')
    
    # === Cookie parfait ===
    def test_perfect_cookie_no_issues(self):
        cookie = {
            'name': 'perfect',
            'attributes': {
                'secure': True, 'httponly': True, 'samesite': 'Lax',
                'domain': 'example.com', 'path': '/app'
            }
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        self.assertEqual(len(result['issues']), 0)
        self.assertTrue(result['is_secure'])
    
    # === Détection cookies sensibles ===
    def test_sensitive_cookie_detection(self):
        self.assertTrue(self.analyzer.is_sensitive_cookie('session_id'))
        self.assertTrue(self.analyzer.is_sensitive_cookie('auth_token'))
        self.assertTrue(self.analyzer.is_sensitive_cookie('user_session'))
        self.assertFalse(self.analyzer.is_sensitive_cookie('analytics'))
    
    # === Combinaison de vulnérabilités (NOUVEAU) ===
    def test_sensitive_cookie_with_multiple_issues(self):
        """Test: Cookie sensible avec multiples vulnérabilités"""
        cookie = {
            'name': 'session_token',
            'attributes': {'secure': False, 'httponly': False, 'samesite': None}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        self.assertTrue(result['is_sensitive'])
        self.assertGreaterEqual(len(result['issues']), 2)


if __name__ == "__main__":
    unittest.main()
