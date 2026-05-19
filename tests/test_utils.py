#!/usr/bin/env python3
"""Tests unitaires pour utils.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.utils import normalize_url, extract_domain, is_same_domain, ColorFormatter


class TestUtils(unittest.TestCase):

    def test_normalize_url(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")
        self.assertEqual(normalize_url("https://example.com"), "https://example.com")
        self.assertEqual(normalize_url("  google.com  "), "https://google.com")

    def test_normalize_url_edge_cases(self):
        with self.assertRaises(ValueError):
            normalize_url("")
        with self.assertRaises(ValueError):
            normalize_url("   ")
        with self.assertRaises(ValueError):
            normalize_url(None)

    def test_extract_domain(self):
        self.assertEqual(extract_domain("https://www.google.com/path"), "www.google.com")
        self.assertEqual(extract_domain("http://sub.domain.com:8080"), "sub.domain.com:8080")

    def test_is_same_domain(self):
        self.assertTrue(is_same_domain("example.com", "www.example.com"))
        self.assertTrue(is_same_domain("www.example.com", "example.com"))
        self.assertFalse(is_same_domain("google.com", "facebook.com"))

    def test_color_formatter_methods_return_none(self):
        cf = ColorFormatter(use_color=False)
        self.assertIsNone(cf.success("test"))
        self.assertIsNone(cf.error("test"))
        self.assertIsNone(cf.warning("test"))
        self.assertIsNone(cf.info("test"))


if __name__ == "__main__":
    unittest.main()
