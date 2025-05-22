"""
Module d'authentification pour les applications web.

Ce module fournit des outils pour automatiser l'authentification
sur des sites web, y compris ceux protégés par captcha.
"""

import logging
import os
import re
from typing import Dict, Optional, Tuple, Union, List

from src.module_3_web.core.requester import WebRequester
from src.module_3_web.core.captcha_solver import CaptchaSolver
from src.module_3_web.utils.tools import extract_forms, extract_links

logger = logging.getLogger(__name__)


class WebAuthenticator:
    """
    Classe pour automatiser l'authentification sur les sites web.
    
    Cette classe fournit des méthodes pour se connecter à des sites web,
    y compris ceux protégés par captcha.
    """
    
    def __init__(self, base_url: str = None, session: WebRequester = None):
        """
        Initialise un nouvel authentificateur web.
        
        Args:
            base_url: URL de base du site
            session: Session WebRequester à utiliser (nouvelle session si None)
        """
        self.session = session if session else WebRequester(base_url)
        self.captcha_solver = None
        
        logger.info("WebAuthenticator initialisé")
    
    def login(self, url: str, credentials: Dict[str, str], 
              form_identifier: Optional[Dict[str, str]] = None) -> bool:
        """
        Effectue une connexion sur un site web.
        
        Args:
            url: URL de la page de connexion
            credentials: Dictionnaire des identifiants (ex: {"username": "user", "password": "pass"})
            form_identifier: Identifiant du formulaire à utiliser (ex: {"id": "login-form"})
            
        Returns:
            True si la connexion a réussi, False sinon
        """
        try:
            logger.info(f"Tentative de connexion à {url}")
            
            # Soumettre le formulaire de connexion
            response = self.session.submit_form(
                url,
                data=credentials,
                form_identifier=form_identifier
            )
            
            # Vérifier si la connexion a réussi (à adapter selon le site)
            success = self._check_login_success(response)
            
            if success:
                logger.info("Connexion réussie")
            else:
                logger.warning("Échec de la connexion")
            
            return success
            
        except Exception as e:
            logger.error(f"Erreur lors de la connexion: {str(e)}")
            return False
    
    def login_with_captcha(self, url: str, credentials: Dict[str, str], 
                          captcha_img_selector: str = "img.captcha", 
                          captcha_field: str = "captcha",
                          form_identifier: Optional[Dict[str, str]] = None) -> bool:
        """
        Effectue une connexion sur un site web protégé par captcha.
        
        Args:
            url: URL de la page de connexion
            credentials: Dictionnaire des identifiants (ex: {"username": "user", "password": "pass"})
            captcha_img_selector: Sélecteur CSS pour l'image captcha
            captcha_field: Nom du champ pour la valeur du captcha
            form_identifier: Identifiant du formulaire à utiliser
            
        Returns:
            True si la connexion a réussi, False sinon
        """
        try:
            logger.info(f"Tentative de connexion avec captcha à {url}")
            
            # Récupérer la page de connexion
            response = self.session.get(url)
            
            # Extraire l'URL de l'image captcha (à adapter selon le site)
            captcha_url = self._extract_captcha_url(response.text, captcha_img_selector)
            
            if not captcha_url:
                logger.error("Impossible de trouver l'image captcha")
                return False
            
            # Initialiser le solveur de captcha si nécessaire
            if not self.captcha_solver:
                self.captcha_solver = CaptchaSolver(preprocess=True)
            
            # Résoudre le captcha
            captcha_text = self.captcha_solver.solve_from_url(captcha_url)
            
            if not captcha_text:
                logger.error("Échec de la résolution du captcha")
                return False
            
            logger.info(f"Captcha résolu: {captcha_text}")
            
            # Ajouter la valeur du captcha aux identifiants
            credentials_with_captcha = credentials.copy()
            credentials_with_captcha[captcha_field] = captcha_text
            
            # Soumettre le formulaire avec les identifiants et le captcha
            response = self.session.submit_form(
                url,
                data=credentials_with_captcha,
                form_identifier=form_identifier
            )
            
            # Vérifier si la connexion a réussi
            success = self._check_login_success(response)
            
            if success:
                logger.info("Connexion avec captcha réussie")
            else:
                logger.warning("Échec de la connexion avec captcha")
            
            return success
            
        except Exception as e:
            logger.error(f"Erreur lors de la connexion avec captcha: {str(e)}")
            return False
    
    def _extract_captcha_url(self, html: str, selector: str) -> Optional[str]:
        """
        Extrait l'URL de l'image captcha à partir du HTML.
        
        Args:
            html: Contenu HTML de la page
            selector: Sélecteur CSS pour l'image captcha
            
        Returns:
            URL de l'image captcha ou None si non trouvée
        """
        # Implémentation simplifiée avec regex
        # Dans un cas réel, on utiliserait BeautifulSoup ou lxml
        img_pattern = f'<{selector.split(".")[-1]}[^>]*class="[^"]*{selector.split(".")[0]}[^"]*"[^>]*src="([^"]+)"'
        match = re.search(img_pattern, html)
        
        if match:
            captcha_url = match.group(1)
            
            # Si l'URL est relative, la convertir en absolue
            if not captcha_url.startswith(('http://', 'https://')):
                base_url = self.session.base_url or ''
                captcha_url = f"{base_url.rstrip('/')}/{captcha_url.lstrip('/')}"
            
            return captcha_url
        
        return None
    
    def _check_login_success(self, response) -> bool:
        """
        Vérifie si la connexion a réussi en analysant la réponse.
        
        Args:
            response: Réponse HTTP après tentative de connexion
            
        Returns:
            True si la connexion a réussi, False sinon
        """
        # Cette méthode doit être adaptée selon le site
        # Voici quelques heuristiques communes:
        
        # 1. Vérifier la redirection vers un dashboard ou page membre
        if 'dashboard' in response.url or 'account' in response.url:
            return True
        
        # 2. Vérifier la présence de certains cookies de session
        cookies = self.session.get_cookies()
        if 'session' in cookies or 'auth' in cookies:
            return True
        
        # 3. Vérifier la présence de messages d'erreur
        error_patterns = [
            'mot de passe incorrect',
            'identifiant invalide',
            'échec de connexion',
            'invalid credentials',
            'login failed'
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response.text.lower():
                return False
        
        # Par défaut, on considère que c'est un échec
        # Dans une implémentation réelle, cette méthode devrait être plus robuste
        return False
    
    def test_captcha_login(self, username: str, password: str, captcha_path: str = None) -> bool:
        """
        Méthode de test pour simuler une connexion avec captcha.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            captcha_path: Chemin vers l'image captcha (générée si None)
            
        Returns:
            True si la simulation de connexion a réussi, False sinon
        """
        # Cette méthode est uniquement pour démonstration et tests
        logger.info(f"Simulation de connexion avec captcha pour l'utilisateur: {username}")
        
        # Générer ou utiliser un captcha existant
        if not captcha_path:
            captcha_path = "captcha_samples/simple.png"
            
            if not os.path.exists(captcha_path):
                try:
                    from generate_captcha import generate_captcha
                    os.makedirs("captcha_samples", exist_ok=True)
                    captcha_text, _ = generate_captcha("ABC123", output_path=captcha_path)
                except ImportError:
                    logger.error("Module generate_captcha non disponible")
                    return False
        
        # Initialiser le solveur de captcha
        if not self.captcha_solver:
            self.captcha_solver = CaptchaSolver(preprocess=True)
        
        # Résoudre le captcha
        captcha_text = self.captcha_solver.solve_from_file(captcha_path)
        logger.info(f"Captcha résolu: {captcha_text}")
        
        # Vérifier si la résolution est correcte (pour le test, on suppose que le captcha est "ABC123")
        expected_captcha = "ABC123"
        success = captcha_text.strip() == expected_captcha
        
        if success:
            logger.info("Simulation de connexion réussie")
        else:
            logger.warning(f"Simulation échouée. Captcha attendu: {expected_captcha}, obtenu: {captcha_text}")
        
        return success 