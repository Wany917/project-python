"""
Tests pour les fonctions de validation.
"""

import unittest
from module_3_web.utils.validation import (
    is_valid_url, is_valid_ip, is_valid_domain, is_valid_email,
    is_valid_port, is_potentially_dangerous, sanitize_url_path,
    validate_form_data
)


class TestValidation(unittest.TestCase):
    """Tests pour les fonctions de validation."""
    
    def test_is_valid_url(self):
        """
        Test la validation d'URLs.
        
        Given: Différentes URLs
        When: is_valid_url est appelé
        Then: Les URLs valides sont correctement identifiées
        """
        # URLs valides
        self.assertTrue(is_valid_url("https://example.com"))
        self.assertTrue(is_valid_url("http://example.com/path"))
        self.assertTrue(is_valid_url("https://example.com/path?param=value"))
        
        # URLs invalides
        self.assertFalse(is_valid_url(""))
        self.assertFalse(is_valid_url("not_a_url"))
        self.assertFalse(is_valid_url("ftp://example.com"))  # Protocole non-HTTP
        self.assertFalse(is_valid_url("http://"))  # Pas de domaine
    
    def test_is_valid_ip(self):
        """
        Test la validation d'adresses IP.
        
        Given: Différentes adresses IP
        When: is_valid_ip est appelé
        Then: Les adresses IP valides sont correctement identifiées
        """
        # IPs valides
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertTrue(is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))  # IPv6
        
        # IPs invalides
        self.assertFalse(is_valid_ip(""))
        self.assertFalse(is_valid_ip("not_an_ip"))
        self.assertFalse(is_valid_ip("256.256.256.256"))  # Hors plage
        self.assertFalse(is_valid_ip("192.168.1"))  # Incomplet
    
    def test_is_valid_domain(self):
        """
        Test la validation de noms de domaine.
        
        Given: Différents noms de domaine
        When: is_valid_domain est appelé
        Then: Les noms de domaine valides sont correctement identifiés
        """
        # Domaines valides
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.com"))
        self.assertTrue(is_valid_domain("example-site.com"))
        
        # Domaines invalides
        self.assertFalse(is_valid_domain(""))
        self.assertFalse(is_valid_domain("invalid"))  # Pas de TLD
        self.assertFalse(is_valid_domain("example."))  # TLD manquant
        self.assertFalse(is_valid_domain("exam ple.com"))  # Espace non autorisé
    
    def test_is_valid_email(self):
        """
        Test la validation d'adresses email.
        
        Given: Différentes adresses email
        When: is_valid_email est appelé
        Then: Les adresses email valides sont correctement identifiées
        """
        # Emails valides
        self.assertTrue(is_valid_email("user@example.com"))
        self.assertTrue(is_valid_email("user.name@example.com"))
        self.assertTrue(is_valid_email("user+tag@example.com"))
        self.assertTrue(is_valid_email("user@sub.example.com"))
        
        # Emails invalides
        self.assertFalse(is_valid_email(""))
        self.assertFalse(is_valid_email("invalid"))  # Pas de @
        self.assertFalse(is_valid_email("user@"))  # Domaine manquant
        self.assertFalse(is_valid_email("@example.com"))  # Utilisateur manquant
        self.assertFalse(is_valid_email("user@example"))  # Pas de TLD
    
    def test_is_valid_port(self):
        """
        Test la validation de numéros de port.
        
        Given: Différents numéros de port
        When: is_valid_port est appelé
        Then: Les numéros de port valides sont correctement identifiés
        """
        # Ports valides
        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port("443"))
        self.assertTrue(is_valid_port(8080))
        self.assertTrue(is_valid_port(1))
        self.assertTrue(is_valid_port(65535))
        
        # Ports invalides
        self.assertFalse(is_valid_port(0))  # Trop petit
        self.assertFalse(is_valid_port(65536))  # Trop grand
        self.assertFalse(is_valid_port(-1))  # Négatif
        self.assertFalse(is_valid_port("abc"))  # Non numérique
        self.assertFalse(is_valid_port(""))  # Vide
    
    def test_is_potentially_dangerous(self):
        """
        Test la détection de chaînes potentiellement dangereuses.
        
        Given: Différentes chaînes de texte
        When: is_potentially_dangerous est appelé
        Then: Les chaînes dangereuses sont correctement identifiées
        """
        # Chaînes dangereuses
        self.assertTrue(is_potentially_dangerous("' OR 1=1 --"))  # Injection SQL
        self.assertTrue(is_potentially_dangerous("<script>alert(1)</script>"))  # XSS
        self.assertTrue(is_potentially_dangerous("../../../etc/passwd"))  # Path traversal
        self.assertTrue(is_potentially_dangerous("; rm -rf /"))  # Commande système
        
        # Chaînes sûres
        self.assertFalse(is_potentially_dangerous(""))
        self.assertFalse(is_potentially_dangerous("safe text"))
        self.assertFalse(is_potentially_dangerous("user123"))
        self.assertFalse(is_potentially_dangerous("example.com"))
    
    def test_sanitize_url_path(self):
        """
        Test la sanitisation de chemins d'URL.
        
        Given: Différents chemins d'URL
        When: sanitize_url_path est appelé
        Then: Les chemins sont correctement sanitizés
        """
        # Test de suppression de caractères suspects
        self.assertEqual(sanitize_url_path("path/to/file"), "path/to/file")
        self.assertEqual(sanitize_url_path("path with spaces"), "pathwithspaces")
        self.assertEqual(sanitize_url_path("path<with>special&chars"), "pathwithspecialchars")
        
        # Test de suppression de traversée de répertoire
        self.assertEqual(sanitize_url_path("../path"), "path")
        self.assertEqual(sanitize_url_path("path/../../file"), "path/file")
        
        # Test avec des chaînes vides ou None
        self.assertEqual(sanitize_url_path(""), "")
        self.assertEqual(sanitize_url_path(None), "")
    
    def test_validate_form_data(self):
        """
        Test la validation de données de formulaire.
        
        Given: Différentes données de formulaire
        When: validate_form_data est appelé
        Then: Les erreurs sont correctement identifiées
        """
        # Test avec des champs requis manquants
        data = {"name": "Test"}
        errors = validate_form_data(data, required_fields=["name", "email"])
        self.assertIn("missing_fields", errors)
        self.assertIn("email", errors["missing_fields"])
        
        # Test avec des champs trop longs
        long_string = "a" * 1001
        data = {"name": "Test", "description": long_string}
        errors = validate_form_data(data, max_length=1000)
        self.assertIn("too_long", errors)
        self.assertIn("description", errors["too_long"])
        
        # Test avec des champs dangereux
        data = {"name": "Test", "input": "'; DROP TABLE users; --"}
        errors = validate_form_data(data)
        self.assertIn("dangerous", errors)
        self.assertIn("input", errors["dangerous"])
        
        # Test avec des données valides
        data = {"name": "Test", "email": "test@example.com"}
        errors = validate_form_data(data, required_fields=["name", "email"])
        self.assertEqual(errors, {})


if __name__ == '__main__':
    unittest.main() 