"""
Tests pour le module de résolution de CAPTCHA.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
from io import BytesIO

# Import conditionnel pour éviter les erreurs si les dépendances ne sont pas installées
try:
    from PIL import Image
    import pytesseract
    from module_3_web.core.captcha_solver import CaptchaSolver, HAS_DEPENDENCIES
    SKIP_TESTS = not HAS_DEPENDENCIES
except ImportError:
    SKIP_TESTS = True


@unittest.skipIf(SKIP_TESTS, "Les dépendances requises ne sont pas installées")
class TestCaptchaSolver(unittest.TestCase):
    """Tests pour la classe CaptchaSolver."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        with patch('pytesseract.pytesseract.get_tesseract_version'):
            self.solver = CaptchaSolver()
        
        # Créer une image de test
        self.test_image = Image.new('RGB', (100, 30), color='white')
        self.image_bytes = BytesIO()
        self.test_image.save(self.image_bytes, format='PNG')
        self.image_bytes.seek(0)
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        self.image_bytes.close()
    
    def test_init(self):
        """
        Test l'initialisation du solveur.
        
        Given: Les dépendances requises sont installées
        When: Un CaptchaSolver est initialisé
        Then: Le solveur est correctement créé avec les paramètres par défaut
        """
        with patch('pytesseract.pytesseract.get_tesseract_version'):
            solver = CaptchaSolver()
            self.assertTrue(solver.preprocess)
    
    def test_init_custom_tesseract(self):
        """
        Test l'initialisation avec un chemin Tesseract personnalisé.
        
        Given: Un chemin vers Tesseract
        When: Un CaptchaSolver est initialisé avec ce chemin
        Then: pytesseract.tesseract_cmd est correctement défini
        """
        tesseract_path = "/usr/local/bin/tesseract"
        with patch('pytesseract.pytesseract') as mock_tesseract:
            with patch('pytesseract.pytesseract.get_tesseract_version'):
                solver = CaptchaSolver(tesseract_cmd=tesseract_path)
                # Vérifier que le chemin a été correctement défini
                self.assertEqual(mock_tesseract.tesseract_cmd, tesseract_path)
    
    @patch('requests.get')
    @patch('module_3_web.core.captcha_solver.CaptchaSolver.solve_from_image')
    def test_solve_from_url(self, mock_solve_from_image, mock_get):
        """
        Test la résolution depuis une URL.
        
        Given: Une URL d'image CAPTCHA
        When: solve_from_url est appelé
        Then: L'image est téléchargée et solve_from_image est appelé
        """
        mock_response = MagicMock()
        mock_response.content = b'image_data'
        mock_get.return_value = mock_response
        mock_solve_from_image.return_value = 'ABC123'
        
        result = self.solver.solve_from_url('https://example.com/captcha.png')
        
        self.assertEqual(result, 'ABC123')
        mock_get.assert_called_once_with('https://example.com/captcha.png', timeout=10)
        mock_solve_from_image.assert_called_once()
    
    @patch('os.path.isfile')
    @patch('module_3_web.core.captcha_solver.CaptchaSolver.solve_from_image')
    def test_solve_from_file_not_found(self, mock_solve_from_image, mock_isfile):
        """
        Test la résolution depuis un fichier inexistant.
        
        Given: Un chemin vers un fichier inexistant
        When: solve_from_file est appelé
        Then: Une FileNotFoundError est levée
        """
        mock_isfile.return_value = False
        with self.assertRaises(FileNotFoundError):
            self.solver.solve_from_file('/path/to/non_existent.png')
        mock_solve_from_image.assert_not_called()
    
    @patch('os.path.isfile')
    @patch('module_3_web.core.captcha_solver.CaptchaSolver.solve_from_image')
    def test_solve_from_file(self, mock_solve_from_image, mock_isfile):
        """
        Test la résolution depuis un fichier.
        
        Given: Un chemin vers un fichier d'image CAPTCHA
        When: solve_from_file est appelé
        Then: solve_from_image est appelé avec ce chemin
        """
        mock_isfile.return_value = True
        mock_solve_from_image.return_value = 'ABC123'
        
        result = self.solver.solve_from_file('/path/to/captcha.png')
        
        self.assertEqual(result, 'ABC123')
        mock_solve_from_image.assert_called_once_with('/path/to/captcha.png', None)
    
    @patch('pytesseract.image_to_string')
    def test_solve_from_image_no_preprocess(self, mock_image_to_string):
        """
        Test la résolution depuis une image sans prétraitement.
        
        Given: Une image de CAPTCHA
        When: solve_from_image est appelé avec preprocess=False
        Then: pytesseract.image_to_string est appelé directement sur l'image
        """
        mock_image_to_string.return_value = 'ABC123'
        
        result = self.solver.solve_from_image(self.test_image, preprocess=False)
        
        self.assertEqual(result, 'ABC123')
        mock_image_to_string.assert_called_once()
        # L'image passée doit être l'image originale
        self.assertEqual(mock_image_to_string.call_args[0][0], self.test_image)
    
    @patch('pytesseract.image_to_string')
    @patch('module_3_web.core.captcha_solver.CaptchaSolver._preprocess_image')
    def test_solve_from_image_with_preprocess(self, mock_preprocess_image, mock_image_to_string):
        """
        Test la résolution depuis une image avec prétraitement.
        
        Given: Une image de CAPTCHA
        When: solve_from_image est appelé avec preprocess=True
        Then: L'image est prétraitée avant d'être passée à pytesseract
        """
        preprocessed_image = MagicMock()
        mock_preprocess_image.return_value = preprocessed_image
        mock_image_to_string.return_value = 'ABC123'
        
        result = self.solver.solve_from_image(self.test_image, preprocess=True)
        
        self.assertEqual(result, 'ABC123')
        mock_preprocess_image.assert_called_once_with(self.test_image)
        mock_image_to_string.assert_called_once()
        # L'image passée doit être l'image prétraitée
        self.assertEqual(mock_image_to_string.call_args[0][0], preprocessed_image)
    
    def test_preprocess_image(self):
        """
        Test le prétraitement d'image.
        
        Given: Une image de CAPTCHA
        When: _preprocess_image est appelé
        Then: Une image prétraitée est retournée
        """
        preprocessed = self.solver._preprocess_image(self.test_image)
        
        # Vérifier que l'image a été convertie en niveaux de gris
        self.assertEqual(preprocessed.mode, 'L')
        
        # Vérifier que l'image a les mêmes dimensions
        self.assertEqual(preprocessed.size, self.test_image.size)
    
    @patch('os.path.isfile')
    @patch('module_3_web.core.captcha_solver.CaptchaSolver._preprocess_image')
    def test_save_preprocessed(self, mock_preprocess_image, mock_isfile):
        """
        Test la sauvegarde d'une image prétraitée.
        
        Given: Une image de CAPTCHA et un chemin de sortie
        When: save_preprocessed est appelé
        Then: L'image prétraitée est sauvegardée au chemin spécifié
        """
        mock_isfile.return_value = True
        
        # Créer un mock de l'image prétraitée
        preprocessed_image = MagicMock()
        mock_preprocess_image.return_value = preprocessed_image
        
        output_path = '/path/to/output.png'
        self.solver.save_preprocessed(self.test_image, output_path)
        
        mock_preprocess_image.assert_called_once_with(self.test_image)
        preprocessed_image.save.assert_called_once_with(output_path)
    
    def test_get_supported_formats(self):
        """
        Test la récupération des formats supportés.
        
        Given: -
        When: get_supported_formats est appelé
        Then: Une liste des extensions supportées est retournée
        """
        formats = CaptchaSolver.get_supported_formats()
        self.assertIsInstance(formats, list)
        self.assertIn('.png', formats)
        self.assertIn('.jpg', formats)


if __name__ == '__main__':
    unittest.main() 