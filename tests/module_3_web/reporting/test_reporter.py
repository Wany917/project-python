"""
Tests pour le module de génération de rapports.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import tempfile
import json
import datetime

from module_3_web.reporting.reporter import WebReporter


class TestWebReporter(unittest.TestCase):
    """Tests pour la classe WebReporter."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        # Créer un répertoire temporaire pour les tests
        self.temp_dir = tempfile.mkdtemp()
        self.reporter = WebReporter(self.temp_dir)
        
        # Données de test
        self.fuzzing_results = {
            "https://example.com/page1": {
                "status_code": 200,
                "content_length": 1024,
                "response_time": 0.5
            },
            "https://example.com/page2": {
                "status_code": 404,
                "content_length": 512,
                "response_time": 0.2
            }
        }
        
        self.vulnerabilities = [
            {
                "name": "SQL Injection",
                "severity": "high",
                "url": "https://example.com/page?id=1",
                "description": "Possible SQL injection in id parameter",
                "details": "Error in SQL syntax when injecting ' OR 1=1",
                "remediation": "Use prepared statements"
            },
            {
                "name": "Cross-Site Scripting",
                "severity": "medium",
                "url": "https://example.com/search?q=test",
                "description": "XSS in search parameter",
                "details": "Input reflected in HTML output",
                "remediation": "Encode all user input"
            }
        ]
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        # Supprimer les fichiers créés pendant les tests
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.remove(os.path.join(root, file))
        os.rmdir(self.temp_dir)
    
    def test_init(self):
        """
        Test l'initialisation du reporter.
        
        Given: Un chemin de répertoire
        When: Un WebReporter est initialisé
        Then: Le reporter est correctement créé avec le répertoire spécifié
        """
        self.assertEqual(self.reporter.output_dir, self.temp_dir)
    
    @patch('os.makedirs')
    def test_init_create_dir(self, mock_makedirs):
        """
        Test l'initialisation avec création de répertoire.
        
        Given: Un chemin vers un répertoire inexistant
        When: Un WebReporter est initialisé avec create_dir=True
        Then: Le répertoire est créé
        """
        with patch('os.path.exists', return_value=False):
            reporter = WebReporter("/path/to/non_existent", create_dir=True)
            mock_makedirs.assert_called_once_with("/path/to/non_existent")
    
    @patch('os.makedirs')
    def test_init_no_create_dir(self, mock_makedirs):
        """
        Test l'initialisation sans création de répertoire.
        
        Given: Un chemin vers un répertoire inexistant
        When: Un WebReporter est initialisé avec create_dir=False
        Then: Le répertoire n'est pas créé
        """
        with patch('os.path.exists', return_value=False):
            reporter = WebReporter("/path/to/non_existent", create_dir=False)
            mock_makedirs.assert_not_called()
    
    @patch('datetime.datetime')
    def test_generate_fuzzing_report(self, mock_datetime):
        """
        Test la génération d'un rapport de fuzzing.
        
        Given: Des résultats de fuzzing
        When: generate_fuzzing_report est appelé
        Then: Un rapport HTML est généré avec les résultats
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_datetime.now.return_value = mock_now
        
        # Substituer la méthode open pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            report_path = self.reporter.generate_fuzzing_report(
                self.fuzzing_results,
                "https://example.com"
            )
            
            # Vérifier que le rapport a été généré
            self.assertTrue(report_path.endswith('.html'))
            mock_file.assert_called_once()
    
    def test_generate_fuzzing_html(self):
        """
        Test la génération du HTML pour un rapport de fuzzing.
        
        Given: Des résultats de fuzzing
        When: _generate_fuzzing_html est appelé
        Then: Un code HTML valide est généré avec les résultats
        """
        html = self.reporter._generate_fuzzing_html(self.fuzzing_results, "https://example.com")
        
        # Vérifier que le HTML contient les éléments attendus
        self.assertIn("https://example.com", html)
        self.assertIn("Rapport de Fuzzing Web", html)
        
        # Vérifier que les résultats sont inclus
        for url in self.fuzzing_results:
            self.assertIn(url, html)
    
    @patch('datetime.datetime')
    def test_generate_vulnerability_report_html(self, mock_datetime):
        """
        Test la génération d'un rapport de vulnérabilités au format HTML.
        
        Given: Des informations sur des vulnérabilités
        When: generate_vulnerability_report est appelé avec format_type='html'
        Then: Un rapport HTML est généré avec les vulnérabilités
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_now.isoformat.return_value = "2023-01-01T12:00:00"
        mock_datetime.now.return_value = mock_now
        
        # Substituer la méthode open pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            report_path = self.reporter.generate_vulnerability_report(
                self.vulnerabilities,
                "https://example.com",
                format_type='html'
            )
            
            # Vérifier que le rapport a été généré
            self.assertTrue(report_path.endswith('.html'))
            mock_file.assert_called_once()
    
    @patch('datetime.datetime')
    def test_generate_vulnerability_report_json(self, mock_datetime):
        """
        Test la génération d'un rapport de vulnérabilités au format JSON.
        
        Given: Des informations sur des vulnérabilités
        When: generate_vulnerability_report est appelé avec format_type='json'
        Then: Un rapport JSON est généré avec les vulnérabilités
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_now.isoformat.return_value = "2023-01-01T12:00:00"
        mock_datetime.now.return_value = mock_now
        
        # Substituer la méthode open et json.dump pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.dump') as mock_json_dump:
                report_path = self.reporter.generate_vulnerability_report(
                    self.vulnerabilities,
                    "https://example.com",
                    format_type='json'
                )
                
                # Vérifier que le rapport a été généré
                self.assertTrue(report_path.endswith('.json'))
                mock_file.assert_called_once()
                mock_json_dump.assert_called_once()
                
                # Vérifier que les vulnérabilités ont été passées à json.dump
                args, kwargs = mock_json_dump.call_args
                self.assertEqual(args[0]['vulnerabilities'], self.vulnerabilities)
    
    @patch('datetime.datetime')
    def test_generate_vulnerability_report_csv(self, mock_datetime):
        """
        Test la génération d'un rapport de vulnérabilités au format CSV.
        
        Given: Des informations sur des vulnérabilités
        When: generate_vulnerability_report est appelé avec format_type='csv'
        Then: Un rapport CSV est généré avec les vulnérabilités
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_datetime.now.return_value = mock_now
        
        # Substituer la méthode open et csv.DictWriter pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('csv.DictWriter') as mock_csv_writer:
                # Simuler l'instance de DictWriter
                mock_writer_instance = MagicMock()
                mock_csv_writer.return_value = mock_writer_instance
                
                report_path = self.reporter.generate_vulnerability_report(
                    self.vulnerabilities,
                    "https://example.com",
                    format_type='csv'
                )
                
                # Vérifier que le rapport a été généré
                self.assertTrue(report_path.endswith('.csv'))
                mock_file.assert_called_once()
                
                # Vérifier que les méthodes de DictWriter ont été appelées
                mock_writer_instance.writeheader.assert_called_once()
                mock_writer_instance.writerows.assert_called_once_with(self.vulnerabilities)
    
    def test_generate_vulnerability_report_unsupported_format(self):
        """
        Test la génération d'un rapport de vulnérabilités avec un format non supporté.
        
        Given: Un format non supporté
        When: generate_vulnerability_report est appelé avec ce format
        Then: Une chaîne vide est retournée
        """
        report_path = self.reporter.generate_vulnerability_report(
            self.vulnerabilities,
            "https://example.com",
            format_type='unsupported'
        )
        
        self.assertEqual(report_path, "")
    
    @patch('datetime.datetime')
    def test_export_requests_history_json(self, mock_datetime):
        """
        Test l'export de l'historique au format JSON.
        
        Given: Un historique de requêtes
        When: export_requests_history est appelé avec format_type='json'
        Then: Un fichier JSON est généré avec l'historique
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_datetime.now.return_value = mock_now
        
        history = [
            {"method": "GET", "url": "https://example.com", "status_code": 200},
            {"method": "POST", "url": "https://example.com/login", "status_code": 302}
        ]
        
        # Substituer la méthode open et json.dump pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.dump') as mock_json_dump:
                export_path = self.reporter.export_requests_history(history, 'json')
                
                # Vérifier que le fichier a été généré
                self.assertTrue(export_path.endswith('.json'))
                mock_file.assert_called_once()
                mock_json_dump.assert_called_once()
                
                # Vérifier que l'historique a été passé à json.dump
                args, kwargs = mock_json_dump.call_args
                self.assertEqual(args[0], history)
    
    @patch('datetime.datetime')
    def test_export_requests_history_csv(self, mock_datetime):
        """
        Test l'export de l'historique au format CSV.
        
        Given: Un historique de requêtes
        When: export_requests_history est appelé avec format_type='csv'
        Then: Un fichier CSV est généré avec l'historique
        """
        # Fixer la date pour éviter les valeurs variables dans les tests
        mock_now = MagicMock()
        mock_now.strftime.return_value = "20230101_120000"
        mock_datetime.now.return_value = mock_now
        
        history = [
            {"method": "GET", "url": "https://example.com", "status_code": 200},
            {"method": "POST", "url": "https://example.com/login", "status_code": 302}
        ]
        
        # Substituer la méthode open et csv.DictWriter pour éviter d'écrire sur le disque
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('csv.DictWriter') as mock_csv_writer:
                # Simuler l'instance de DictWriter
                mock_writer_instance = MagicMock()
                mock_csv_writer.return_value = mock_writer_instance
                
                export_path = self.reporter.export_requests_history(history, 'csv')
                
                # Vérifier que le fichier a été généré
                self.assertTrue(export_path.endswith('.csv'))
                mock_file.assert_called_once()
                
                # Vérifier que les méthodes de DictWriter ont été appelées
                mock_writer_instance.writeheader.assert_called_once()
                mock_writer_instance.writerows.assert_called_once()


if __name__ == '__main__':
    unittest.main() 