"""
Tests pour le module de requêtes HTTP.
"""

import unittest
from unittest.mock import patch, MagicMock, call, mock_open
import json
import time
import re
from io import BytesIO

from src.module_3_web.core.requester import WebRequester


class TestWebRequester(unittest.TestCase):
    """Tests pour la classe WebRequester."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        self.valid_url = "https://example.com"
        self.valid_path = "/api/users"
        self.requester = WebRequester(self.valid_url)
    
    def test_init_with_base_url(self):
        """
        Test l'initialisation avec une URL de base.
        
        Given: Une URL de base valide
        When: Un WebRequester est initialisé avec cette URL
        Then: Le WebRequester est correctement créé avec les paramètres par défaut
        """
        requester = WebRequester(self.valid_url)
        self.assertEqual(requester.base_url, self.valid_url)
        self.assertEqual(requester.timeout, 10)  # Valeur par défaut
        self.assertIsNotNone(requester.session)
        self.assertIsNotNone(requester.user_agents)
        self.assertEqual(len(requester.history), 0)
    
    def test_init_without_base_url(self):
        """
        Test l'initialisation sans URL de base.
        
        Given: Aucune URL de base
        When: Un WebRequester est initialisé sans URL
        Then: Le WebRequester est correctement créé avec base_url=None
        """
        requester = WebRequester()
        self.assertIsNone(requester.base_url)
        self.assertEqual(requester.timeout, 10)  # Valeur par défaut
        self.assertIsNotNone(requester.session)
        self.assertIsNotNone(requester.user_agents)
        self.assertEqual(len(requester.history), 0)
    
    def test_build_url_absolute(self):
        """
        Test la construction d'une URL avec une URL absolue.
        
        Given: Une URL absolue
        When: _build_url est appelé avec cette URL
        Then: L'URL est retournée telle quelle
        """
        absolute_url = "https://other-example.com/path"
        result = self.requester._build_url(absolute_url)
        self.assertEqual(result, absolute_url)
    
    def test_build_url_relative(self):
        """
        Test la construction d'une URL avec une URL relative.
        
        Given: Une URL relative et une URL de base
        When: _build_url est appelé avec l'URL relative
        Then: L'URL absolue est correctement construite
        """
        relative_url = "/api/users"
        expected = f"{self.valid_url}{relative_url}"
        result = self.requester._build_url(relative_url)
        self.assertEqual(result, expected)
    
    def test_build_url_relative_no_base(self):
        """
        Test la construction d'une URL relative sans URL de base.
        
        Given: Une URL relative sans URL de base
        When: _build_url est appelé
        Then: Une ValueError est levée
        """
        requester = WebRequester()  # Sans URL de base
        with self.assertRaises(ValueError):
            requester._build_url("/api/users")
    
    @patch('requests.Session.get')
    def test_get_request(self, mock_get):
        """
        Test l'envoi d'une requête GET.
        
        Given: Une URL à requêter
        When: get est appelé
        Then: La méthode requests.Session.get est appelée avec les bons paramètres
        """
        mock_response = MagicMock()
        mock_get.return_value = mock_response
        
        result = self.requester.get(self.valid_path)
        
        self.assertEqual(result, mock_response)
        mock_get.assert_called_once()
        # Vérifier que l'URL a été correctement construite
        call_args = mock_get.call_args[0][0]
        self.assertEqual(call_args, f"{self.valid_url}{self.valid_path}")
    
    @patch('requests.Session.post')
    def test_post_request(self, mock_post):
        """
        Test l'envoi d'une requête POST.
        
        Given: Une URL et des données
        When: post est appelé
        Then: La méthode requests.Session.post est appelée avec les bons paramètres
        """
        mock_response = MagicMock()
        mock_post.return_value = mock_response
        
        data = {"username": "test", "password": "password"}
        result = self.requester.post(self.valid_path, data=data)
        
        self.assertEqual(result, mock_response)
        mock_post.assert_called_once()
        # Vérifier que l'URL et les données ont été correctement passées
        call_args, call_kwargs = mock_post.call_args
        self.assertEqual(call_args[0], f"{self.valid_url}{self.valid_path}")
        self.assertEqual(call_kwargs['data'], data)
    
    @patch('requests.Session.post')
    def test_post_json(self, mock_post):
        """
        Test l'envoi d'une requête POST avec des données JSON.
        
        Given: Une URL et des données JSON
        When: post est appelé avec json_data
        Then: La méthode requests.Session.post est appelée avec les bons paramètres
        """
        mock_response = MagicMock()
        mock_post.return_value = mock_response
        
        json_data = {"username": "test", "password": "password"}
        result = self.requester.post(self.valid_path, json_data=json_data)
        
        self.assertEqual(result, mock_response)
        mock_post.assert_called_once()
        # Vérifier que l'en-tête Content-Type a été ajouté
        call_args, call_kwargs = mock_post.call_args
        self.assertIn('Content-Type', call_kwargs['headers'])
        self.assertEqual(call_kwargs['headers']['Content-Type'], 'application/json')
        self.assertEqual(call_kwargs['json'], json_data)
    
    def test_submit_form_no_forms(self):
        """
        Test la soumission d'un formulaire lorsqu'aucun formulaire n'est trouvé.
        
        Given: Une page sans formulaire
        When: submit_form est appelé
        Then: Une ValueError est levée
        """
        # Patcher la fonction extract_forms au niveau du module où elle est importée
        with patch('src.module_3_web.core.requester.extract_forms') as mock_extract:
            # Configurer le mock pour qu'il retourne une liste vide
            mock_extract.return_value = []
            
            # Patcher la méthode get pour qu'elle retourne une réponse simulée
            with patch.object(self.requester, 'get') as mock_get:
                mock_response = MagicMock()
                mock_response.text = "<html><body>No form here</body></html>"
                mock_get.return_value = mock_response
                
                # Vérifier que la ValueError est levée
                with self.assertRaises(ValueError):
                    self.requester.submit_form(self.valid_path, {})
                
                # Vérifier que get a été appelé
                mock_get.assert_called_once()
                # Vérifier que extract_forms a été appelé
                mock_extract.assert_called_once()
    
    def test_submit_form_post(self):
        """
        Test la soumission d'un formulaire POST.
        
        Given: Une page avec un formulaire POST
        When: submit_form est appelé
        Then: La méthode post est appelée avec les bons paramètres
        """
        # Formulaire simulé
        form = {
            'action': '/submit',
            'method': 'post',
            'id': 'login-form',
            'fields': [
                {'name': 'csrf_token', 'type': 'hidden', 'value': '12345'},
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''}
            ]
        }
        
        # Patcher la fonction extract_forms au niveau du module où elle est importée
        with patch('src.module_3_web.core.requester.extract_forms') as mock_extract:
            # Configurer le mock pour qu'il retourne le formulaire simulé
            mock_extract.return_value = [form]
            
            # Patcher les méthodes get et post
            with patch.object(self.requester, 'get') as mock_get:
                with patch.object(self.requester, 'post') as mock_post:
                    # Configurer les mocks
                    mock_response = MagicMock()
                    mock_get.return_value = mock_response
                    mock_post.return_value = MagicMock()
                    
                    # Données de formulaire
                    form_data = {'username': 'test', 'password': 'pass123'}
                    
                    # Appeler la méthode à tester
                    self.requester.submit_form(self.valid_path, form_data)
                    
                    # Vérifier que les méthodes ont été appelées
                    mock_get.assert_called_once_with(self.valid_path, headers=None)
                    mock_extract.assert_called_once()
                    
                    # Vérifier que post a été appelé avec les bonnes données
                    mock_post.assert_called_once()
                    args, kwargs = mock_post.call_args
                    
                    # Les données doivent inclure le champ caché et les données fournies
                    expected_data = {'csrf_token': '12345', 'username': 'test', 'password': 'pass123'}
                    self.assertEqual(kwargs.get('data'), expected_data)
    
    def test_cookies_management(self):
        """
        Test la gestion des cookies.
        
        Given: Un WebRequester avec des cookies
        When: get_cookies et clear_session sont appelés
        Then: Les cookies sont correctement retournés puis effacés
        """
        # Simuler des cookies dans la session
        cookie = MagicMock()
        cookie.name = "session"
        cookie.value = "abc123"
        self.requester.session.cookies = MagicMock()
        self.requester.session.cookies.__iter__.return_value = [cookie]
        
        cookies = self.requester.get_cookies()
        self.assertEqual(cookies, {"session": "abc123"})
        
        self.requester.clear_session()
        self.requester.session.cookies.clear.assert_called_once()
    
    def test_export_history_json(self):
        """
        Test l'export de l'historique au format JSON.
        
        Given: Un historique de requêtes
        When: export_history('json') est appelé
        Then: L'historique est correctement exporté au format JSON
        """
        # Préparer un historique
        self.requester.history = [
            {"method": "GET", "url": "https://example.com", "status_code": 200},
            {"method": "POST", "url": "https://example.com/login", "status_code": 302}
        ]
        
        # Patcher json.dumps au lieu d'utiliser le mock_open qui est plus compliqué à gérer
        expected_json = json.dumps(self.requester.history, indent=2)
        
        with patch('json.dumps', return_value=expected_json) as mock_json_dump:
            result = self.requester.export_history('json')
            
            mock_json_dump.assert_called_once_with(self.requester.history, indent=2)
            self.assertEqual(result, expected_json)


if __name__ == '__main__':
    unittest.main() 