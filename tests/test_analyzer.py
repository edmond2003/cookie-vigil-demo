#!/usr/bin/env python3
"""Tests unitaires pour analyzer.py - règles OWASP, classification et corrélations."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.analyzer import CookieAnalyzer


class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = CookieAnalyzer()
        self.ctx_https = {'is_https': True, 'force_check': False}
        self.ctx_http = {'is_https': False, 'force_check': False}
        self.ctx_force = {'is_https': False, 'force_check': True}

    def _issue(self, result, rule_id):
        matches = [i for i in result['issues'] if i['id'] == rule_id]
        return matches[0] if matches else None

    # === Classification intelligente ===

    def test_classify_session_cookie(self):
        cookie = {'name': 'session_token', 'value': 'a' * 32, 'attributes': {}}
        self.assertEqual(self.analyzer.classify_cookie(cookie), 'SESSION')

    def test_classify_jwt_cookie(self):
        cookie = {
            'name': 'access_cookie',
            'value': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature',
            'attributes': {}
        }
        self.assertEqual(self.analyzer.classify_cookie(cookie), 'JWT')

    def test_classify_tracking_cookie(self):
        cookie = {'name': 'tracking_id', 'value': 'track_123', 'attributes': {}}
        self.assertEqual(self.analyzer.classify_cookie(cookie), 'TRACKING')

    def test_classify_functional_cookie(self):
        cookie = {'name': 'theme', 'value': 'dark', 'attributes': {}}
        self.assertEqual(self.analyzer.classify_cookie(cookie), 'FUNCTIONAL')

    # === Sévérité contextualisée ===

    def test_secure_missing_session_is_critical(self):
        cookie = {
            'name': 'session_token',
            'value': 'a' * 32,
            'attributes': {'secure': False, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'SECURE_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'CRITICAL')
        self.assertEqual(result['risk_level'], 'CRITICAL')

    def test_secure_missing_functional_is_low(self):
        cookie = {
            'name': 'theme',
            'value': 'dark',
            'attributes': {'secure': False, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'SECURE_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'LOW')
        self.assertEqual(result['risk_level'], 'LOW')

    def test_httponly_missing_session_is_high(self):
        cookie = {
            'name': 'session_id',
            'value': 'a' * 32,
            'attributes': {'secure': True, 'httponly': False, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'HTTPONLY_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'HIGH')

    def test_httponly_missing_functional_is_info(self):
        cookie = {
            'name': 'theme',
            'value': 'dark',
            'attributes': {'secure': True, 'httponly': False, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'HTTPONLY_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'INFO')

    def test_samesite_missing_session_is_medium(self):
        cookie = {
            'name': 'session_id',
            'value': 'a' * 32,
            'attributes': {'secure': True, 'httponly': True, 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'SAMESITE_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'MEDIUM')

    def test_samesite_missing_functional_is_low(self):
        cookie = {
            'name': 'theme',
            'value': 'dark',
            'attributes': {'secure': True, 'httponly': True, 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'SAMESITE_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'LOW')

    def test_samesite_none_without_secure_sensitive_is_critical(self):
        cookie = {
            'name': 'session_token',
            'value': 'a' * 32,
            'attributes': {'secure': False, 'httponly': True, 'samesite': 'None', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'SAMESITE_NONE_INSECURE')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'CRITICAL')

    def test_domain_too_broad_functional_is_low(self):
        cookie = {
            'name': 'theme',
            'value': 'dark',
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'domain': '.example.com', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'DOMAIN_TOO_BROAD')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'LOW')

    def test_path_too_broad_functional_is_info(self):
        cookie = {
            'name': 'theme',
            'value': 'dark',
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'PATH_TOO_BROAD')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'INFO')

    def test_expires_long_sensitive_is_medium(self):
        cookie = {
            'name': 'long_lived_token',
            'value': 'a' * 32,
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/app', 'max-age': 31536000}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'EXPIRES_LONG')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'MEDIUM')

    # === Préfixes ===

    def test_secure_prefix_missing_high(self):
        cookie = {
            'name': '__Secure-test',
            'value': 'abc',
            'attributes': {'secure': False, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'PREFIX_SECURE_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'HIGH')

    def test_host_prefix_missing_high(self):
        cookie = {
            'name': '__Host-test',
            'value': 'abc',
            'attributes': {'secure': False, 'domain': 'example.com', 'path': '/'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'PREFIX_HOST_MISSING')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'HIGH')

    # === Token faible et JWT ===

    def test_weak_token_high(self):
        cookie = {
            'name': 'session_id',
            'value': 'abc123',
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'WEAK_TOKEN')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'HIGH')

    def test_weak_token_not_triggered_on_username(self):
        cookie = {
            'name': 'username',
            'value': 'admin',
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        self.assertIsNone(self._issue(result, 'WEAK_TOKEN'))

    def test_jwt_detected_info(self):
        cookie = {
            'name': 'jwt_token',
            'value': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature',
            'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        issue = self._issue(result, 'JWT_DETECTED')
        self.assertIsNotNone(issue)
        self.assertEqual(issue['risk'], 'INFO')
        self.assertEqual(result['category'], 'JWT')

    # === Corrélations ===

    def test_session_exposure_correlation(self):
        cookie = {
            'name': 'session_token',
            'value': 'a' * 32,
            'attributes': {'secure': False, 'httponly': False, 'samesite': None, 'path': '/'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        correlation_ids = [c['id'] for c in result.get('correlations', [])]
        self.assertIn('SESSION_EXPOSURE_COMBINED', correlation_ids)
        self.assertIn('CSRF_EXPOSURE', correlation_ids)
        self.assertEqual(result['risk_level'], 'CRITICAL')

    def test_jwt_xss_correlation(self):
        cookie = {
            'name': 'jwt_token',
            'value': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature',
            'attributes': {'secure': True, 'httponly': False, 'samesite': 'Lax', 'path': '/app'}
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        correlation_ids = [c['id'] for c in result.get('correlations', [])]
        self.assertIn('JWT_XSS_EXPOSURE', correlation_ids)

    # === Score et statistiques ===

    def test_analyze_cookies_category_counts(self):
        cookies = [
            {'name': 'session_token', 'value': 'a' * 32, 'attributes': {'secure': True, 'httponly': True, 'samesite': 'Lax', 'path': '/'}},
            {'name': 'tracking_id', 'value': 'track_123', 'attributes': {'secure': False, 'httponly': False, 'path': '/'}},
        ]
        analysis = self.analyzer.analyze_cookies(cookies, self.ctx_https)
        self.assertEqual(analysis['statistics']['total'], 2)
        self.assertEqual(analysis['statistics']['category_counts']['SESSION'], 1)
        self.assertEqual(analysis['statistics']['category_counts']['TRACKING'], 1)

    def test_security_score_weighted(self):
        stats = {
            'total': 4,
            'risk_counts': {
                'CRITICAL': 1,
                'HIGH': 1,
                'MEDIUM': 1,
                'LOW': 1,
                'INFO': 0
            }
        }
        score = self.analyzer.calculate_security_score(stats)
        self.assertEqual(score, 83)

    def test_perfect_cookie_no_issues(self):
        cookie = {
            'name': 'perfect',
            'value': 'value',
            'attributes': {
                'secure': True,
                'httponly': True,
                'samesite': 'Lax',
                'domain': 'example.com',
                'path': '/app'
            }
        }
        result = self.analyzer.analyze_cookie(cookie, self.ctx_https)
        self.assertEqual(len(result['issues']), 0)
        self.assertTrue(result['is_secure'])
        self.assertEqual(result['risk_level'], 'INFO')


if __name__ == "__main__":
    unittest.main()
