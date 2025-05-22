"""
Tests pour le module de fuzzing.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import sys

from src.module_3_web.core.fuzzer import WebFuzzer


class TestWebFuzzer(unittest.TestCase):
    """Tests pour la classe WebFuzzer."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.valid_url = "https://example.com"
        self.test_wordlist = ["admin", "login", "dashboard", "config"]
    
    def test_init_valid_url(self):
        """
        Test l'initialisation avec une URL valide.
        
        Given: Une URL valide
        When: Un WebFuzzer est initialisé avec cette URL
        Then: Le WebFuzzer est correctement créé avec les paramètres par défaut
        """
        fuzzer = WebFuzzer(self.valid_url)
        self.assertEqual(fuzzer.base_url, self.valid_url)
        self.assertEqual(fuzzer.max_threads, 10)  # Valeur par défaut
        self.assertEqual(fuzzer.timeout, 10)  # Valeur par défaut
        self.assertIsNotNone(fuzzer.session)
        self.assertIsNotNone(fuzzer.user_agents)
        self.assertIsNotNone(fuzzer.headers)
    
    def test_init_invalid_url(self):
        """
        Test l'initialisation avec une URL invalide.
        
        Given: Une URL invalide
        When: Un WebFuzzer est initialisé avec cette URL
        Then: Une ValueError est levée
        """
        with self.assertRaises(ValueError):
            WebFuzzer("not_a_valid_url")
    
    def test_fuzz_paths_empty_wordlist(self):
        """
        Test le fuzzing avec une wordlist vide.
        
        Given: Une wordlist vide
        When: fuzz_paths est appelé
        Then: Un dictionnaire vide est retourné
        """
        # Simuler l'appel à load_wordlist
        with patch('src.module_3_web.utils.tools.os.path.isfile', return_value=True):
            with patch('builtins.open', mock_open(read_data="")):
                fuzzer = WebFuzzer(self.valid_url)
                # Aucun mot dans la wordlist, donc load_wordlist retournera []
                results = fuzzer.fuzz_paths("dummy_wordlist.txt")
                
                # Vérifier le résultat
                self.assertEqual(results, {})
    
    def test_fuzz_paths_with_extensions(self):
        """
        Test le fuzzing avec différentes extensions.
        
        Given: Une wordlist et une liste d'extensions
        When: fuzz_paths est appelé avec ces paramètres
        Then: Le ThreadPoolExecutor est appelé avec les paramètres corrects
        """
        # Préparer le contenu de la wordlist
        wordlist_content = "\n".join(self.test_wordlist)
        
        # Patcher tous les appels nécessaires
        with patch('src.module_3_web.utils.tools.os.path.isfile', return_value=True):
            with patch('builtins.open', mock_open(read_data=wordlist_content)):
                with patch('src.module_3_web.core.fuzzer.ThreadPoolExecutor') as mock_executor:
                    # Configurer le mock de ThreadPoolExecutor
                    mock_executor_instance = MagicMock()
                    mock_executor.return_value.__enter__.return_value = mock_executor_instance
                    
                    # Exécuter la fonction à tester
                    extensions = ['.php', '.html']
                    fuzzer = WebFuzzer(self.valid_url)
                    results = fuzzer.fuzz_paths("dummy_wordlist.txt", extensions)
                    
                    # Vérifier que l'executor a été appelé pour chaque combinaison
                    expected_calls = len(self.test_wordlist) * len(extensions)
                    self.assertEqual(mock_executor_instance.submit.call_count, expected_calls)
    
    def test_detect_anomalies(self):
        """
        Test la détection d'anomalies dans les réponses.
        
        Given: Une réponse contenant des anomalies potentielles
        When: _detect_anomalies est appelé sur cette réponse
        Then: Les anomalies sont correctement détectées
        """
        fuzzer = WebFuzzer(self.valid_url)
        
        # Test avec une injection SQL
        anomalies = fuzzer._detect_anomalies("Error in SQL syntax near...")
        self.assertIn("sql syntax", anomalies)
        
        # Test avec une erreur PHP
        anomalies = fuzzer._detect_anomalies("FATAL ERROR: Undefined index...")
        self.assertIn("fatal error", anomalies)
        
        # Test avec une trace de stack
        anomalies = fuzzer._detect_anomalies("Stack trace: #0 /var/www/...")
        self.assertIn("stack trace", anomalies)
        
        # Test sans anomalie
        anomalies = fuzzer._detect_anomalies("This is a normal response.")
        self.assertEqual(anomalies, [])


if __name__ == '__main__':
    unittest.main() 