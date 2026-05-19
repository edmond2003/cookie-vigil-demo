#!/usr/bin/env python3
"""Tests unitaires pour collector.py - parsing, métadonnées et redirections."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from src.collector import CookieCollector


class TestCollector(unittest.TestCase):

    def setUp(self):
        self.collector = CookieCollector(timeout=5, verify_ssl=False)

    def _mock_response(self, url, status_code=200, cookies=None, history=None, is_redirect=False):
        response = MagicMock()
        response.status_code = status_code
        response.url = url
        response.history = history or []
        response.headers = {}
        response.is_redirect = is_redirect
        response.is_permanent_redirect = False
        response.raw.headers.getlist.return_value = cookies or []
        return response

    # === Parsing des cookies ===

    def test_parse_simple_cookie(self):
        cookie_str = 'session=abc123; Path=/; HttpOnly; Secure'
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'session')
        self.assertEqual(cookies[0]['value'], 'abc123')
        self.assertEqual(cookies[0]['raw_value_for_analysis'], 'abc123')
        self.assertEqual(cookies[0]['value_length'], 6)
        self.assertIsNotNone(cookies[0]['value_sha256'])
        self.assertTrue(cookies[0]['attributes']['secure'])
        self.assertTrue(cookies[0]['attributes']['httponly'])

    def test_parse_complex_cookie(self):
        cookie_str = 'user=john; Domain=.example.com; Path=/app; SameSite=Lax; Max-Age=3600'
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'user')
        self.assertEqual(cookies[0]['attributes']['domain'], '.example.com')
        self.assertEqual(cookies[0]['attributes']['path'], '/app')
        self.assertEqual(cookies[0]['attributes']['samesite'], 'Lax')
        self.assertEqual(cookies[0]['attributes']['max-age'], '3600')

    def test_secure_false_positive_is_avoided(self):
        cookie_str = 'secure_id=abc123; Path=/'
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'secure_id')
        self.assertFalse(cookies[0]['attributes']['secure'])

    def test_httponly_false_positive_is_avoided(self):
        cookie_str = 'my_httponly_value=abc123; Path=/'
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(len(cookies), 1)
        self.assertFalse(cookies[0]['attributes']['httponly'])

    def test_parse_cookie_without_attributes(self):
        cookie_str = 'tracking=xyz123'
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'tracking')
        self.assertFalse(cookies[0]['attributes']['secure'])
        self.assertFalse(cookies[0]['attributes']['httponly'])

    def test_parse_invalid_cookie(self):
        cookies = self.collector._parse_set_cookie("invalid !@#$")
        self.assertEqual(len(cookies), 0)

    def test_truncate_value_keeps_analysis_value(self):
        long_value = "a" * 100
        cookie_str = f"session={long_value}; Path=/; Secure; HttpOnly"
        cookies = self.collector._parse_set_cookie(cookie_str)

        self.assertEqual(cookies[0]['value_length'], 100)
        self.assertEqual(cookies[0]['raw_value_for_analysis'], long_value)

    # === Collecte HTTP mockée ===

    @patch('src.collector.requests.Session.get')
    def test_collect_from_url_mock_success(self, mock_get):
        mock_response = self._mock_response(
            url="https://example.com",
            cookies=['session=abc; Secure; HttpOnly; Path=/']
        )
        mock_get.return_value = mock_response

        result = self.collector.collect_from_url("https://example.com")

        self.assertIn('cookies', result)
        self.assertEqual(len(result['cookies']), 1)
        self.assertEqual(result['cookies'][0]['name'], 'session')
        self.assertIn('proof', result['cookies'][0])
        self.assertEqual(result['cookies'][0]['proof']['source_url'], 'https://example.com')

    @patch('src.collector.requests.Session.get')
    def test_collect_from_url_collects_redirect_cookies(self, mock_get):
        redirect_response = self._mock_response(
            url="https://example.com/redirect",
            status_code=302,
            cookies=['redirect_cookie=abc; Path=/; Secure'],
            is_redirect=True
        )
        final_response = self._mock_response(
            url="https://example.com/final",
            status_code=200,
            cookies=['final_cookie=xyz; Path=/; Secure'],
            history=[redirect_response],
            is_redirect=False
        )

        mock_get.return_value = final_response

        result = self.collector.collect_from_url("https://example.com")

        names = [c['name'] for c in result['cookies']]
        self.assertIn('redirect_cookie', names)
        self.assertIn('final_cookie', names)
        self.assertEqual(len(result['cookies']), 2)
        self.assertEqual(result['redirect_chain'], ['https://example.com/redirect'])

    @patch('src.collector.requests.Session.get')
    def test_collect_from_url_mock_error(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")

        result = self.collector.collect_from_url("https://unreachable.com")

        self.assertIn('error', result)
        self.assertEqual(len(result['cookies']), 0)

    def test_truncate_value(self):
        long_value = "a" * 100
        truncated = self.collector._truncate_value(long_value, max_len=50)

        self.assertEqual(len(truncated), 53)
        self.assertTrue(truncated.endswith("..."))


if __name__ == "__main__":
    unittest.main()
