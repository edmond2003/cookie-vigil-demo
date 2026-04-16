#!/usr/bin/env python3
"""Tests unitaires pour le module collector.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from src.collector import CookieCollector


class TestCollector(unittest.TestCase):
    
    def setUp(self):
        self.collector = CookieCollector(timeout=5, verify_ssl=False)
    
    # === Parsing des cookies ===
    def test_parse_simple_cookie(self):
        cookie_str = 'session=abc123; Path=/; HttpOnly; Secure'
        cookies = self.collector._parse_set_cookie(cookie_str)
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'session')
        self.assertTrue(cookies[0]['attributes']['secure'])
        self.assertTrue(cookies[0]['attributes']['httponly'])
    
    def test_parse_complex_cookie(self):
        cookie_str = 'user=john; Domain=.example.com; Path=/app; SameSite=Lax; Max-Age=3600'
        cookies = self.collector._parse_set_cookie(cookie_str)
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'user')
        self.assertEqual(cookies[0]['attributes']['samesite'], 'Lax')
    
    def test_parse_multiple_cookies_in_one_header(self):
        cookie_str = 'session=abc; user=john'
        cookies = self.collector._parse_set_cookie(cookie_str)
        self.assertEqual(len(cookies), 2)
        names = [c['name'] for c in cookies]
        self.assertIn('session', names)
        self.assertIn('user', names)
    
    def test_parse_cookie_without_attributes(self):
        cookie_str = 'tracking=xyz123'
        cookies = self.collector._parse_set_cookie(cookie_str)
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]['name'], 'tracking')
    
    def test_parse_invalid_cookie(self):
        cookies = self.collector._parse_set_cookie("invalid !@#$")
        self.assertEqual(len(cookies), 0)
    
    # === Tests HTTP avec mock (NOUVEAU) ===
    @patch('src.collector.requests.Session.get')
    def test_collect_from_url_mock_success(self, mock_get):
        """Test: Requête HTTP réussie avec mock"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://example.com"
        mock_response.raw.headers.getlist.return_value = ['session=abc; Secure']
        mock_get.return_value = mock_response
        
        result = self.collector.collect_from_url("https://example.com")
        
        self.assertIn('cookies', result)
        self.assertEqual(len(result['cookies']), 1)
        self.assertEqual(result['cookies'][0]['name'], 'session')
    
    @patch('src.collector.requests.Session.get')
    def test_collect_from_url_mock_error(self, mock_get):
        """Test: Requête HTTP avec erreur"""
        mock_get.side_effect = Exception("Connection refused")
        
        result = self.collector.collect_from_url("https://unreachable.com")
        
        self.assertIn('error', result)
        self.assertEqual(len(result['cookies']), 0)
    
    # === Truncation ===
    def test_truncate_value(self):
        long_value = "a" * 100
        truncated = self.collector._truncate_value(long_value, max_len=50)
        self.assertEqual(len(truncated), 53)
        self.assertTrue(truncated.endswith("..."))


if __name__ == "__main__":
    unittest.main()
