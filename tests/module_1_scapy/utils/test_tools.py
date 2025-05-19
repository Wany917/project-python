"""
Tests pour le module d'utilitaires.
"""

import logging
import unittest
from unittest.mock import patch, MagicMock

from module_1_scapy.utils.tools import setup_logging, is_valid_ip


class TestLoggingSetup(unittest.TestCase):
    """Tests pour les fonctions de configuration du logging."""
    
    @patch('logging.StreamHandler')
    @patch('logging.FileHandler')
    @patch('logging.basicConfig')
    def test_setup_logging_with_file(self, mock_basic_config, mock_file_handler, mock_stream_handler):
        """Test de la configuration du logging avec un fichier."""
        # Given
        log_level = "DEBUG"
        log_file = "test.log"
        mock_formatter = MagicMock()
        mock_stream_handler.return_value.setFormatter.return_value = None
        mock_file_handler.return_value.setFormatter.return_value = None
        
        # When
        with patch('logging.Formatter', return_value=mock_formatter):
            setup_logging(log_level, log_file)
        
        # Then
        mock_stream_handler.assert_called_once()
        mock_file_handler.assert_called_once_with(log_file)
        mock_basic_config.assert_called_once()
    
    @patch('logging.StreamHandler')
    @patch('logging.FileHandler')
    @patch('logging.basicConfig')
    def test_setup_logging_without_file(self, mock_basic_config, mock_file_handler, mock_stream_handler):
        """Test de la configuration du logging sans fichier."""
        # Given
        log_level = "INFO"
        log_file = None
        mock_formatter = MagicMock()
        mock_stream_handler.return_value.setFormatter.return_value = None
        
        # When
        with patch('logging.Formatter', return_value=mock_formatter):
            setup_logging(log_level, log_file)
        
        # Then
        mock_stream_handler.assert_called_once()
        mock_file_handler.assert_not_called()
        mock_basic_config.assert_called_once()
    
    def test_setup_logging_invalid_level(self):
        """Test de la configuration du logging avec un niveau invalide."""
        # Given
        log_level = "INVALID"
        log_file = None
        
        # When/Then
        with self.assertRaises(ValueError):
            setup_logging(log_level, log_file)


class TestIPUtils(unittest.TestCase):
    """Tests pour les fonctions liées aux adresses IP."""
    
    def test_is_valid_ip_valid_addresses(self):
        """Test de validation d'adresses IP valides."""
        # Given
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "8.8.8.8",
            "255.255.255.255"
        ]
        
        # When/Then
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(is_valid_ip(ip))
    
    def test_is_valid_ip_invalid_addresses(self):
        """Test de validation d'adresses IP invalides."""
        # Given
        invalid_ips = [
            "256.0.0.1",
            "192.168.1",
            "192.168.1.300",
            "192.168.1.1.1",
            "abc.def.ghi.jkl",
            "localhost",
            "",
            " ",
            "192.168.1.",
            ".192.168.1.1"
        ]
        
        # When/Then
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_valid_ip(ip))


if __name__ == "__main__":
    unittest.main() 