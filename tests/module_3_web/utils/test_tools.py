"""
Tests pour les fonctions d'outils.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import tempfile

from module_3_web.utils.tools import (
    get_user_agents, load_wordlist, extract_forms, extract_links,
    generate_random_params, parse_robots_txt
)


class TestTools(unittest.TestCase):
    """Tests pour les fonctions d'outils."""
    
    def test_get_user_agents(self):
        """
        Test la récupération des User-Agents.
        
        Given: -
        When: get_user_agents est appelé
        Then: Une liste non vide de User-Agents est retournée
        """
        user_agents = get_user_agents()
        self.assertIsInstance(user_agents, list)
        self.assertTrue(len(user_agents) > 0)
        
        # Vérifier que tous les éléments sont des chaînes
        for ua in user_agents:
            self.assertIsInstance(ua, str)
    
    def test_load_wordlist_file_not_found(self):
        """
        Test le chargement d'une wordlist avec un fichier inexistant.
        
        Given: Un chemin vers un fichier inexistant
        When: load_wordlist est appelé
        Then: Une liste vide est retournée
        """
        with patch('os.path.isfile', return_value=False):
            words = load_wordlist("/path/to/non_existent.txt")
            self.assertEqual(words, [])
    
    def test_load_wordlist(self):
        """
        Test le chargement d'une wordlist.
        
        Given: Un fichier avec des mots
        When: load_wordlist est appelé
        Then: Une liste des mots du fichier est retournée
        """
        # Contenu simulé du fichier
        file_content = "word1\nword2\nword3\n"
        
        with patch('os.path.isfile', return_value=True):
            with patch('builtins.open', mock_open(read_data=file_content)):
                words = load_wordlist("/path/to/wordlist.txt")
                self.assertEqual(words, ["word1", "word2", "word3"])
    
    def test_extract_forms(self):
        """
        Test l'extraction de formulaires HTML.
        
        Given: Un contenu HTML avec des formulaires
        When: extract_forms est appelé
        Then: Les formulaires sont correctement extraits
        """
        html = """
        <html>
        <body>
            <form action="/login" method="post" id="login-form">
                <input type="hidden" name="csrf_token" value="12345">
                <input type="text" name="username" required>
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            <form action="/search" method="get">
                <input type="text" name="q">
                <input type="submit" value="Search">
            </form>
        </body>
        </html>
        """
        
        forms = extract_forms(html)
        
        self.assertEqual(len(forms), 2)
        
        # Vérifier le premier formulaire
        self.assertEqual(forms[0]['action'], "/login")
        self.assertEqual(forms[0]['method'], "post")
        self.assertEqual(forms[0]['id'], "login-form")
        
        # Vérifier les champs du premier formulaire
        fields = forms[0]['fields']
        self.assertEqual(len(fields), 3)  # 3 champs avec nom (sans le submit)
        
        # Vérifier le premier champ (csrf_token)
        csrf_field = next(field for field in fields if field['name'] == 'csrf_token')
        self.assertEqual(csrf_field['type'], 'hidden')
        self.assertEqual(csrf_field['value'], '12345')
        
        # Vérifier le deuxième formulaire
        self.assertEqual(forms[1]['action'], "/search")
        self.assertEqual(forms[1]['method'], "get")
    
    def test_extract_links(self):
        """
        Test l'extraction de liens HTML.
        
        Given: Un contenu HTML avec des liens
        When: extract_links est appelé
        Then: Les liens sont correctement extraits
        """
        html = """
        <html>
        <body>
            <a href="https://example.com">Lien absolu</a>
            <a href="/path/to/page">Lien relatif</a>
            <a href="#section">Ancre</a>
            <a href="javascript:void(0)">JavaScript</a>
            <a href="https://example.com/duplicate">Lien dupliqué</a>
            <a href="https://example.com/duplicate">Lien dupliqué</a>
        </body>
        </html>
        """
        
        # Test sans base_url
        links = extract_links(html)
        self.assertEqual(len(links), 3)  # 3 liens uniques (sans ancres et javascript)
        self.assertIn("https://example.com", links)
        self.assertIn("/path/to/page", links)
        
        # Test avec base_url
        links = extract_links(html, "https://base-url.com")
        self.assertEqual(len(links), 3)  # 3 liens uniques
        self.assertIn("https://example.com", links)
        self.assertIn("https://base-url.com/path/to/page", links)  # Lien relatif converti
    
    def test_generate_random_params(self):
        """
        Test la génération de paramètres aléatoires.
        
        Given: Une liste de noms de paramètres
        When: generate_random_params est appelé
        Then: Un dictionnaire de paramètres avec des valeurs aléatoires est retourné
        """
        param_names = ["param1", "param2", "param3"]
        
        # Test avec valeurs par défaut
        params = generate_random_params(param_names)
        self.assertEqual(len(params), 3)
        for name in param_names:
            self.assertIn(name, params)
            self.assertIsInstance(params[name], str)
        
        # Test avec valeurs personnalisées
        custom_values = ["value1", "value2"]
        params = generate_random_params(param_names, custom_values)
        self.assertEqual(len(params), 3)
        for name in param_names:
            self.assertIn(name, params)
            self.assertIn(params[name], custom_values)
    
    def test_parse_robots_txt(self):
        """
        Test l'analyse d'un fichier robots.txt.
        
        Given: Un contenu de fichier robots.txt
        When: parse_robots_txt est appelé
        Then: Les règles sont correctement extraites
        """
        robots_content = """
        User-agent: *
        Disallow: /admin/
        Disallow: /private/
        Allow: /public/
        
        User-agent: GoogleBot
        Disallow: /no-google/
        
        Sitemap: https://example.com/sitemap.xml
        """
        
        rules = parse_robots_txt(robots_content)
        
        # Vérifier les règles pour tous les agents
        self.assertIn("/admin/", rules["disallow"])
        self.assertIn("/private/", rules["disallow"])
        self.assertIn("/public/", rules["allow"])
        
        # Vérifier les règles spécifiques à un agent
        self.assertIn("GoogleBot", rules["user_agents"])
        self.assertIn("/no-google/", rules["user_agents"]["GoogleBot"]["disallow"])
        
        # Vérifier le sitemap
        self.assertIn("https://example.com/sitemap.xml", rules["sitemaps"])


if __name__ == '__main__':
    unittest.main() 