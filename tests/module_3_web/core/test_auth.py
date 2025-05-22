"""
Tests pour le module d'authentification.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import tempfile

from src.module_3_web.core.auth import WebAuthenticator
from src.module_3_web.core.requester import WebRequester
from src.module_3_web.core.captcha_solver import CaptchaSolver


class TestWebAuthenticator(unittest.TestCase):
    """Tests pour la classe WebAuthenticator."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.base_url = "https://example.com"
        self.auth = WebAuthenticator(self.base_url)
    
    def test_init(self):
        """
        Test l'initialisation de l'authentificateur.
        
        Given: Une URL de base
        When: Un WebAuthenticator est initialisé avec cette URL
        Then: L'authentificateur est correctement créé
        """
        self.assertIsInstance(self.auth.session, WebRequester)
        self.assertEqual(self.auth.session.base_url, self.base_url)
        self.assertIsNone(self.auth.captcha_solver)
    
    def test_init_with_session(self):
        """
        Test l'initialisation avec une session existante.
        
        Given: Une session WebRequester existante
        When: Un WebAuthenticator est initialisé avec cette session
        Then: L'authentificateur utilise la session fournie
        """
        session = WebRequester("https://other-example.com")
        auth = WebAuthenticator(session=session)
        
        self.assertEqual(auth.session, session)
        self.assertEqual(auth.session.base_url, "https://other-example.com")
    
    @patch('src.module_3_web.core.requester.WebRequester.submit_form')
    def test_login(self, mock_submit_form):
        """
        Test la connexion standard (sans captcha).
        
        Given: Des identifiants valides
        When: login est appelé
        Then: La méthode submit_form est appelée avec les bons paramètres
        """
        # Configurer le mock
        mock_response = MagicMock()
        mock_response.url = "https://example.com/dashboard"
        mock_submit_form.return_value = mock_response
        
        # Effectuer la connexion
        credentials = {"username": "test", "password": "pass123"}
        result = self.auth.login("/login", credentials)
        
        # Vérifier que submit_form a été appelé correctement
        mock_submit_form.assert_called_once_with("/login", data=credentials, form_identifier=None)
        
        # Vérifier que la connexion a réussi
        self.assertTrue(result)
    
    @patch('src.module_3_web.core.requester.WebRequester.submit_form')
    def test_login_failed(self, mock_submit_form):
        """
        Test la connexion échouée.
        
        Given: Des identifiants invalides
        When: login est appelé
        Then: La méthode retourne False
        """
        # Configurer le mock
        mock_response = MagicMock()
        mock_response.url = "https://example.com/login"
        mock_response.text = "Invalid credentials. Please try again."
        mock_submit_form.return_value = mock_response
        
        # Effectuer la connexion
        credentials = {"username": "test", "password": "wrong"}
        result = self.auth.login("/login", credentials)
        
        # Vérifier que la connexion a échoué
        self.assertFalse(result)
    
    @patch('src.module_3_web.core.requester.WebRequester.get')
    @patch('src.module_3_web.core.auth.WebAuthenticator._extract_captcha_url')
    @patch('src.module_3_web.core.captcha_solver.CaptchaSolver.solve_from_url')
    @patch('src.module_3_web.core.requester.WebRequester.submit_form')
    def test_login_with_captcha(self, mock_submit_form, mock_solve, mock_extract_url, mock_get):
        """
        Test la connexion avec captcha.
        
        Given: Des identifiants valides et une image captcha
        When: login_with_captcha est appelé
        Then: Le captcha est résolu et le formulaire est soumis avec les bonnes données
        """
        # Configurer les mocks
        mock_response = MagicMock()
        mock_response.text = "<html><img class='captcha' src='/captcha.png'></html>"
        mock_get.return_value = mock_response
        
        mock_extract_url.return_value = "https://example.com/captcha.png"
        mock_solve.return_value = "ABC123"
        
        mock_form_response = MagicMock()
        mock_form_response.url = "https://example.com/dashboard"
        mock_submit_form.return_value = mock_form_response
        
        # Appeler la fonction à tester
        credentials = {"username": "test", "password": "pass123"}
        result = self.auth.login_with_captcha("/login", credentials)
        
        # Vérifier que les méthodes ont été appelées correctement
        mock_get.assert_called_once_with("/login")
        mock_extract_url.assert_called_once()
        mock_solve.assert_called_once_with("https://example.com/captcha.png")
        
        # Vérifier que submit_form a été appelé avec les bonnes données
        expected_data = {"username": "test", "password": "pass123", "captcha": "ABC123"}
        mock_submit_form.assert_called_once_with("/login", data=expected_data, form_identifier=None)
        
        # Vérifier que la connexion a réussi
        self.assertTrue(result)
    
    def test_extract_captcha_url(self):
        """
        Test l'extraction de l'URL du captcha.
        
        Given: Un HTML contenant une image captcha
        When: _extract_captcha_url est appelé
        Then: L'URL du captcha est correctement extraite
        """
        html = """
        <html>
            <body>
                <form>
                    <img class="captcha" src="/captcha/image.png">
                    <input type="text" name="captcha">
                </form>
            </body>
        </html>
        """
        
        url = self.auth._extract_captcha_url(html, "img.captcha")
        expected_url = "https://example.com/captcha/image.png"
        
        self.assertEqual(url, expected_url)
    
    @patch('os.path.exists')
    @patch('src.module_3_web.core.captcha_solver.CaptchaSolver.solve_from_file')
    def test_test_captcha_login(self, mock_solve, mock_exists):
        """
        Test la méthode de simulation de login avec captcha.
        
        Given: Un chemin vers une image captcha
        When: test_captcha_login est appelé
        Then: La méthode retourne True si le captcha est correctement résolu
        """
        # Configurer les mocks
        mock_exists.return_value = True
        mock_solve.return_value = "ABC123"
        
        # Appeler la fonction à tester
        result = self.auth.test_captcha_login("testuser", "testpass", "captcha_samples/simple.png")
        
        # Vérifier que les méthodes ont été appelées correctement
        mock_exists.assert_called_once()
        mock_solve.assert_called_once_with("captcha_samples/simple.png")
        
        # Vérifier que le test a réussi
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main() 