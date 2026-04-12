#!/usr/bin/env python3
"""
Tests unitaires pour le module utils.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.utils import normalize_url, extract_domain, is_same_domain, ColorFormatter

class TestUtils(unittest.TestCase):
    
    def test_normalize_url_adds_https(self):
        result = normalize_url("example.com")
        self.assertEqual(result, "https://example.com")
        print("  ✅ normalize_url: ajout HTTPS OK")
    
    def test_normalize_url_preserves_http(self):
        result = normalize_url("http://example.com")
        self.assertEqual(result, "http://example.com")
        print("  ✅ normalize_url: conservation HTTP OK")
    
    def test_normalize_url_preserves_https(self):
        result = normalize_url("https://secure.com")
        self.assertEqual(result, "https://secure.com")
        print("  ✅ normalize_url: conservation HTTPS OK")
    
    def test_normalize_url_strips_spaces(self):
        result = normalize_url("  google.com  ")
        self.assertEqual(result, "https://google.com")
        print("  ✅ normalize_url: nettoyage espaces OK")
    
    def test_extract_domain_from_https(self):
        result = extract_domain("https://www.example.com/path")
        self.assertEqual(result, "www.example.com")
        print("  ✅ extract_domain: HTTPS OK")
    
    def test_extract_domain_from_http(self):
        result = extract_domain("http://sub.domain.com:8080/page")
        self.assertEqual(result, "sub.domain.com:8080")
        print("  ✅ extract_domain: HTTP OK")
    
    def test_extract_domain_with_www(self):
        result = extract_domain("https://www.google.com/search")
        self.assertEqual(result, "www.google.com")
        print("  ✅ extract_domain: avec www OK")
    
    def test_extract_domain_simple(self):
        # Pour les URLs sans protocole, on utilise normalize_url d'abord
        normalized = normalize_url("example.com")
        result = extract_domain(normalized)
        self.assertEqual(result, "example.com")
        print("  ✅ extract_domain: sans protocole OK")
    
    def test_is_same_domain_identical(self):
        result = is_same_domain("example.com", "example.com")
        self.assertTrue(result)
        print("  ✅ is_same_domain: identiques OK")
    
    def test_is_same_domain_with_www(self):
        result = is_same_domain("example.com", "www.example.com")
        self.assertTrue(result)
        print("  ✅ is_same_domain: avec/sans www OK")
    
    def test_is_same_domain_different(self):
        result = is_same_domain("google.com", "facebook.com")
        self.assertFalse(result)
        print("  ✅ is_same_domain: différents OK")
    
    def test_color_formatter_returns_string(self):
        result = ColorFormatter.colorize("test", "CRITICAL")
        self.assertIsInstance(result, str)
        print("  ✅ ColorFormatter: retourne string OK")
    
    def test_color_formatter_different_levels(self):
        levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for level in levels:
            result = ColorFormatter.colorize("test", level)
            self.assertIsInstance(result, str)
        print("  ✅ ColorFormatter: tous niveaux OK")

def run_tests():
    print("\n" + "="*50)
    print("🧪 TESTS UNITAIRES - MODULE UTILS")
    print("="*50 + "\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestUtils)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    
    print("\n" + "="*50)
    print(f"✅ Tests passés: {result.testsRun - len(result.failures)}/{result.testsRun}")
    if result.failures:
        print(f"❌ Échecs: {len(result.failures)}")
    print("="*50)
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
EOF
