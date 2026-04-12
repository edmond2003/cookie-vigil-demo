#!/usr/bin/env python3
"""
Tests unitaires détaillés pour le module analyzer.py
Teste chaque règle de sécurité individuellement
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.analyzer import CookieAnalyzer

class TestAnalyzerRules(unittest.TestCase):
    """Test chaque règle de sécurité indépendamment"""
    
    def setUp(self):
        self.analyzer = CookieAnalyzer()
        self.https_context = {'is_https': True}
        self.http_context = {'is_https': False}
    
    # ========== RÈGLE 1: SECURE_MISSING ==========
    
    def test_rule_secure_missing_critical(self):
        """RÈGLE 1: Cookie sans Secure sur HTTPS → CRITICAL"""
        cookie = {'name': 'test', 'attributes': {'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SECURE_MISSING' for i in result['issues'])
        self.assertTrue(rule_triggered, "La règle SECURE_MISSING aurait dû se déclencher")
        
        rule_risk = next(i['risk'] for i in result['issues'] if i['id'] == 'SECURE_MISSING')
        self.assertEqual(rule_risk, 'CRITICAL')
        print("  ✅ RÈGLE 1: SECURE_MISSING - CRITICAL OK")
    
    def test_rule_secure_present_ok(self):
        """RÈGLE 1: Cookie avec Secure → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'secure': True}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SECURE_MISSING' for i in result['issues'])
        self.assertFalse(rule_triggered, "La règle SECURE_MISSING ne devrait pas se déclencher")
        print("  ✅ RÈGLE 1: Secure présent - OK")
    
    # ========== RÈGLE 2: HTTPONLY_MISSING ==========
    
    def test_rule_httponly_missing_high(self):
        """RÈGLE 2: Cookie sans HttpOnly → HIGH"""
        cookie = {'name': 'test', 'attributes': {'httponly': False}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'HTTPONLY_MISSING' for i in result['issues'])
        self.assertTrue(rule_triggered, "La règle HTTPONLY_MISSING aurait dû se déclencher")
        
        rule_risk = next(i['risk'] for i in result['issues'] if i['id'] == 'HTTPONLY_MISSING')
        self.assertEqual(rule_risk, 'HIGH')
        print("  ✅ RÈGLE 2: HTTPONLY_MISSING - HIGH OK")
    
    def test_rule_httponly_present_ok(self):
        """RÈGLE 2: Cookie avec HttpOnly → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'httponly': True}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'HTTPONLY_MISSING' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 2: HttpOnly présent - OK")
    
    # ========== RÈGLE 3: SAMESITE_MISSING ==========
    
    def test_rule_samesite_missing_medium(self):
        """RÈGLE 3: Cookie sans SameSite → MEDIUM"""
        cookie = {'name': 'test', 'attributes': {}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SAMESITE_MISSING' for i in result['issues'])
        self.assertTrue(rule_triggered, "La règle SAMESITE_MISSING aurait dû se déclencher")
        
        rule_risk = next(i['risk'] for i in result['issues'] if i['id'] == 'SAMESITE_MISSING')
        self.assertEqual(rule_risk, 'MEDIUM')
        print("  ✅ RÈGLE 3: SAMESITE_MISSING - MEDIUM OK")
    
    def test_rule_samesite_present_ok(self):
        """RÈGLE 3: Cookie avec SameSite → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'samesite': 'Lax'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SAMESITE_MISSING' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 3: SameSite présent - OK")
    
    # ========== RÈGLE 4: SAMESITE_NONE_INSECURE ==========
    
    def test_rule_samesite_none_without_secure_critical(self):
        """RÈGLE 4: SameSite=None sans Secure → CRITICAL"""
        cookie = {'name': 'test', 'attributes': {'samesite': 'None', 'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SAMESITE_NONE_INSECURE' for i in result['issues'])
        self.assertTrue(rule_triggered)
        
        rule_risk = next(i['risk'] for i in result['issues'] if i['id'] == 'SAMESITE_NONE_INSECURE')
        self.assertEqual(rule_risk, 'CRITICAL')
        print("  ✅ RÈGLE 4: SAMESITE_NONE_INSECURE - CRITICAL OK")
    
    def test_rule_samesite_none_with_secure_ok(self):
        """RÈGLE 4: SameSite=None avec Secure → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'samesite': 'None', 'secure': True}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'SAMESITE_NONE_INSECURE' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 4: SameSite=None avec Secure - OK")
    
    # ========== RÈGLE 5: DOMAIN_TOO_BROAD ==========
    
    def test_rule_domain_too_broad_medium(self):
        """RÈGLE 5: Domaine commençant par '.' → MEDIUM"""
        cookie = {'name': 'test', 'attributes': {'domain': '.example.com'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'DOMAIN_TOO_BROAD' for i in result['issues'])
        self.assertTrue(rule_triggered)
        print("  ✅ RÈGLE 5: DOMAIN_TOO_BROAD - MEDIUM OK")
    
    def test_rule_specific_domain_ok(self):
        """RÈGLE 5: Domaine spécifique → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'domain': 'specific.example.com'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'DOMAIN_TOO_BROAD' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 5: Domaine spécifique - OK")
    
    # ========== RÈGLE 6: PATH_TOO_BROAD ==========
    
    def test_rule_path_too_broad_low(self):
        """RÈGLE 6: Path = '/' → LOW"""
        cookie = {'name': 'test', 'attributes': {'path': '/'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PATH_TOO_BROAD' for i in result['issues'])
        self.assertTrue(rule_triggered)
        print("  ✅ RÈGLE 6: PATH_TOO_BROAD - LOW OK")
    
    def test_rule_specific_path_ok(self):
        """RÈGLE 6: Path spécifique → pas d'alerte"""
        cookie = {'name': 'test', 'attributes': {'path': '/app/admin'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PATH_TOO_BROAD' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 6: Path spécifique - OK")
    
    # ========== RÈGLE 7: PREFIX_SECURE_MISSING ==========
    
    def test_rule_secure_prefix_without_secure_high(self):
        """RÈGLE 7: Préfixe __Secure- sans Secure → HIGH"""
        cookie = {'name': '__Secure-test', 'attributes': {'secure': False}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PREFIX_SECURE_MISSING' for i in result['issues'])
        self.assertTrue(rule_triggered)
        print("  ✅ RÈGLE 7: PREFIX_SECURE_MISSING - HIGH OK")
    
    def test_rule_secure_prefix_with_secure_ok(self):
        """RÈGLE 7: Préfixe __Secure- avec Secure → OK"""
        cookie = {'name': '__Secure-test', 'attributes': {'secure': True}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PREFIX_SECURE_MISSING' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 7: __Secure- avec Secure - OK")
    
    # ========== RÈGLE 8: PREFIX_HOST_MISSING ==========
    
    def test_rule_host_prefix_missing_requirements_high(self):
        """RÈGLE 8: Préfixe __Host- mal configuré → HIGH"""
        cookie = {'name': '__Host-test', 'attributes': {'secure': False, 'domain': 'example.com', 'path': '/'}}
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PREFIX_HOST_MISSING' for i in result['issues'])
        self.assertTrue(rule_triggered)
        print("  ✅ RÈGLE 8: PREFIX_HOST_MISSING - HIGH OK")
    
    def test_rule_host_prefix_correct_ok(self):
        """RÈGLE 8: Préfixe __Host- bien configuré → OK"""
        cookie = {'name': '__Host-test', 'attributes': {'secure': True, 'path': '/'}}
        # Pas de domain, path=/, secure=True
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        rule_triggered = any(i['id'] == 'PREFIX_HOST_MISSING' for i in result['issues'])
        self.assertFalse(rule_triggered)
        print("  ✅ RÈGLE 8: __Host- bien configuré - OK")
    
    # ========== TESTS COMPLÉMENTAIRES ==========
    
    def test_multiple_rules_on_same_cookie(self):
        """Test: Un cookie peut déclencher plusieurs règles"""
        cookie = {
            'name': 'bad',
            'attributes': {
                'secure': False,
                'httponly': False,
                'domain': '.example.com',
                'path': '/'
            }
        }
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        # Devrait déclencher au moins 3 règles
        self.assertGreaterEqual(len(result['issues']), 3)
        print(f"  ✅ Multi-règles: {len(result['issues'])} règles déclenchées")
    
    def test_perfect_cookie_no_issues(self):
        """Test: Cookie parfait → aucune issue"""
        cookie = {
            'name': 'perfect',
            'attributes': {
                'secure': True,
                'httponly': True,
                'samesite': 'Strict',
                'domain': 'example.com',
                'path': '/app'
            }
        }
        result = self.analyzer.analyze_cookie(cookie, self.https_context)
        
        self.assertEqual(len(result['issues']), 0)
        self.assertTrue(result['is_secure'])
        print("  ✅ Cookie parfait: 0 issue")

def run_all_tests():
    """Exécute tous les tests"""
    print("\n" + "="*60)
    print("🧪 TESTS UNITAIRES - MODULE ANALYZER (RÈGLES OWASP)")
    print("="*60 + "\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAnalyzerRules)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("📊 RÉSULTAT DES TESTS ANALYZER")
    print("="*60)
    print(f"✅ Règles testées: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"❌ Échecs: {len(result.failures)}")
    print(f"⚠️  Erreurs: {len(result.errors)}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
EOF
