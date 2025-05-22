"""
Module pour la résolution de CAPTCHA.

Ce module fournit des outils pour résoudre automatiquement les CAPTCHA
en utilisant des techniques d'OCR et de traitement d'image.
"""

import os
import logging
import tempfile
from typing import Optional, Dict, Any, Tuple, List, Union
from io import BytesIO
import requests

try:
    from PIL import Image, ImageFilter, ImageEnhance
    import pytesseract
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False

logger = logging.getLogger(__name__)


class CaptchaSolver:
    """
    Classe pour la résolution automatisée de CAPTCHA.
    
    Cette classe utilise des techniques de traitement d'images et d'OCR
    pour tenter de résoudre des CAPTCHA simples basés sur du texte.
    """
    
    def __init__(self, tesseract_cmd: str = None, preprocess: bool = True):
        """
        Initialise un nouveau solveur de CAPTCHA.
        
        Args:
            tesseract_cmd: Chemin vers l'exécutable Tesseract OCR
            preprocess: Activer le prétraitement d'image par défaut
            
        Raises:
            ImportError: Si les dépendances requises ne sont pas installées
        """
        if not HAS_DEPENDENCIES:
            raise ImportError(
                "Les dépendances requises ne sont pas installées. "
                "Installez PIL et pytesseract avec: "
                "pip install pillow pytesseract"
            )
        
        self.preprocess = preprocess
        
        # Configuration de Tesseract OCR
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        
        try:
            pytesseract.get_tesseract_version()
            logger.info("Tesseract OCR initialisé avec succès")
        except Exception as e:
            logger.warning(f"Tesseract OCR non disponible: {str(e)}")
        
        logger.info("CaptchaSolver initialisé")
    
    def solve_from_url(self, url: str, preprocess: bool = None) -> str:
        """
        Résout un CAPTCHA à partir d'une URL d'image.
        
        Args:
            url: URL de l'image CAPTCHA
            preprocess: Activer le prétraitement d'image (remplace la valeur par défaut)
            
        Returns:
            Texte extrait du CAPTCHA
            
        Raises:
            requests.RequestException: Si l'image ne peut pas être téléchargée
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            image_data = BytesIO(response.content)
            return self.solve_from_image(image_data, preprocess)
        
        except requests.RequestException as e:
            logger.error(f"Erreur lors du téléchargement du CAPTCHA: {str(e)}")
            raise
    
    def solve_from_file(self, file_path: str, preprocess: bool = None) -> str:
        """
        Résout un CAPTCHA à partir d'un fichier image.
        
        Args:
            file_path: Chemin vers le fichier image
            preprocess: Activer le prétraitement d'image (remplace la valeur par défaut)
            
        Returns:
            Texte extrait du CAPTCHA
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
        
        return self.solve_from_image(file_path, preprocess)
    
    def solve_from_image(self, image_source: Union[str, BytesIO, Image.Image], 
                        preprocess: bool = None) -> str:
        """
        Résout un CAPTCHA à partir d'une image.
        
        Args:
            image_source: Source de l'image (chemin, BytesIO ou objet PIL.Image)
            preprocess: Activer le prétraitement d'image (remplace la valeur par défaut)
            
        Returns:
            Texte extrait du CAPTCHA
        """
        if isinstance(image_source, (str, BytesIO)):
            image = Image.open(image_source)
        else:
            image = image_source
        
        should_preprocess = self.preprocess if preprocess is None else preprocess
        if should_preprocess:
            image = self._preprocess_image(image)
        
        try:
            custom_config = r'--oem 3 --psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
            text = pytesseract.image_to_string(image, config=custom_config)
            
            text = text.strip()
            
            logger.info(f"CAPTCHA résolu: '{text}'")
            return text
        
        except Exception as e:
            logger.error(f"Erreur lors de la reconnaissance OCR: {str(e)}")
            return ""
    
    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Prétraite une image pour améliorer la reconnaissance OCR.
        
        Args:
            image: Image à prétraiter
            
        Returns:
            Image prétraitée
        """
        image = image.convert('L')
        
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)
        
        threshold = 140
        image = image.point(lambda p: 255 if p > threshold else 0)
        
        image = image.filter(ImageFilter.MedianFilter(size=3))
        
        # Redimensionnement (optionnel, selon le cas)
        # image = image.resize((image.width * 2, image.height * 2), Image.BICUBIC)
        
        return image
    
    def save_preprocessed(self, image_source: Union[str, BytesIO, Image.Image], 
                          output_path: str) -> str:
        """
        Prétraite et sauvegarde une image pour inspection.
        
        Args:
            image_source: Source de l'image (chemin, BytesIO ou objet PIL.Image)
            output_path: Chemin de sauvegarde de l'image prétraitée
            
        Returns:
            Chemin de l'image sauvegardée
        """
        if isinstance(image_source, (str, BytesIO)):
            image = Image.open(image_source)
        else:
            image = image_source
        
        processed = self._preprocess_image(image)
        
        processed.save(output_path)
        logger.info(f"Image prétraitée sauvegardée: {output_path}")
        
        return output_path
    
    def solve_recaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        """
        Méthode stub pour la résolution de reCAPTCHA (non implémentée).
        
        Cette méthode pourrait être connectée à des services tiers de résolution
        comme 2captcha ou Anti-Captcha.
        
        Args:
            site_key: Clé du site reCAPTCHA
            page_url: URL de la page contenant le reCAPTCHA
            
        Returns:
            Token de résolution ou None si échec
        """
        logger.warning("La résolution de reCAPTCHA n'est pas implémentée par défaut")
        return None
    
    @staticmethod
    def get_supported_formats() -> List[str]:
        """
        Retourne les formats d'image supportés.
        
        Returns:
            Liste des extensions de formats supportés
        """
        return ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.webp'] 