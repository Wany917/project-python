"""
Module pour le fuzzing d'applications web.

Ce module fournit des outils pour tester les applications web
en injectant des données aléatoires ou prédéfinies.
"""

import random
import logging
from typing import Dict, List, Union, Optional, Any, Callable
import requests
from concurrent.futures import ThreadPoolExecutor

from module_3_web.utils.tools import get_user_agents, load_wordlist
from module_3_web.utils.validation import is_valid_url

logger = logging.getLogger(__name__)


class WebFuzzer:
    """
    Classe pour effectuer du fuzzing sur des applications web.
    
    Cette classe permet de tester les applications web en injectant des données
    aléatoires ou prédéfinies dans différents points d'entrée (URL, paramètres, formulaires).
    """
    
    def __init__(self, base_url: str, max_threads: int = 10, timeout: int = 10):
        """
        Initialise un nouveau fuzzer web.
        
        Args:
            base_url: URL de base de l'application à tester
            max_threads: Nombre maximum de threads pour les requêtes parallèles
            timeout: Timeout pour les requêtes en secondes
        
        Raises:
            ValueError: Si l'URL de base n'est pas valide
        """
        if not is_valid_url(base_url):
            raise ValueError(f"URL invalide: {base_url}")
        
        self.base_url = base_url
        self.max_threads = max_threads
        self.timeout = timeout
        self.session = requests.Session()
        self.user_agents = get_user_agents()
        
        # Paramètres par défaut pour les requêtes
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
        }
        
        logger.info(f"WebFuzzer initialisé pour {base_url}")
    
    def fuzz_paths(self, wordlist_path: str, extensions: List[str] = None) -> Dict[str, Any]:
        """
        Teste l'existence de chemins dans l'application web.
        
        Args:
            wordlist_path: Chemin vers le fichier de wordlist
            extensions: Liste des extensions à tester (ex: ['.php', '.html'])
            
        Returns:
            Dictionnaire des résultats avec les codes de statut et les temps de réponse
        """
        paths = load_wordlist(wordlist_path)
        if not paths:
            logger.error(f"Impossible de charger la wordlist: {wordlist_path}")
            return {}
        
        results = {}
        extensions = extensions or ['', '.php', '.html', '.js', '.txt']
        
        logger.info(f"Démarrage du fuzzing de chemins avec {len(paths)} mots et {len(extensions)} extensions")
        
        def test_path(path: str, ext: str) -> None:
            test_url = f"{self.base_url.rstrip('/')}/{path}{ext}"
            try:
                # Randomiser l'User-Agent pour éviter la détection
                self.headers['User-Agent'] = random.choice(self.user_agents)
                
                response = self.session.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                # Enregistrer les résultats intéressants (non 404)
                if response.status_code != 404:
                    results[test_url] = {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'response_time': response.elapsed.total_seconds()
                    }
                    
                    logger.info(f"[{response.status_code}] {test_url}")
            
            except requests.RequestException as e:
                logger.debug(f"Erreur lors du test de {test_url}: {str(e)}")
        
        # Exécution parallèle des tests
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for path in paths:
                for ext in extensions:
                    executor.submit(test_path, path, ext)
        
        logger.info(f"Fuzzing de chemins terminé. {len(results)} résultats trouvés.")
        return results
    
    def fuzz_parameters(self, target_url: str, params: List[str], payloads: List[str]) -> Dict[str, Any]:
        """
        Teste les paramètres d'une URL avec différentes charges utiles.
        
        Args:
            target_url: URL cible à tester
            params: Liste des noms de paramètres à tester
            payloads: Liste des charges utiles à injecter
            
        Returns:
            Dictionnaire des résultats avec les réponses anormales
        """
        if not is_valid_url(target_url):
            raise ValueError(f"URL cible invalide: {target_url}")
        
        results = {}
        
        logger.info(f"Démarrage du fuzzing de paramètres avec {len(params)} paramètres et {len(payloads)} payloads")
        
        def test_param(param: str, payload: str) -> None:
            test_params = {param: payload}
            try:
                self.headers['User-Agent'] = random.choice(self.user_agents)
                
                response = self.session.get(
                    target_url,
                    params=test_params,
                    headers=self.headers,
                    timeout=self.timeout
                )
                
                # Détection d'anomalies (erreurs, réponses inhabituelles)
                if (
                    'error' in response.text.lower() or
                    'exception' in response.text.lower() or
                    'syntax error' in response.text.lower() or
                    'warning' in response.text.lower() or
                    response.status_code >= 500
                ):
                    key = f"{param}={payload}"
                    results[key] = {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'response_time': response.elapsed.total_seconds(),
                        'anomalies': self._detect_anomalies(response.text)
                    }
                    
                    logger.info(f"Anomalie détectée: {param}={payload} -> {response.status_code}")
            
            except requests.RequestException as e:
                logger.debug(f"Erreur lors du test de {param}={payload}: {str(e)}")
        
        # Exécution parallèle des tests
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for param in params:
                for payload in payloads:
                    executor.submit(test_param, param, payload)
        
        logger.info(f"Fuzzing de paramètres terminé. {len(results)} anomalies trouvées.")
        return results
    
    def _detect_anomalies(self, content: str) -> List[str]:
        """
        Détecte les anomalies dans le contenu d'une réponse.
        
        Args:
            content: Contenu de la réponse HTTP
            
        Returns:
            Liste des anomalies détectées
        """
        anomalies = []
        
        error_patterns = [
            'sql syntax', 'mysql error', 'postgresql error', 'sqlite error',
            'odbc error', 'oracle error', 'syntax error',
            'exception', 'stack trace', 'undefined index',
            'fatal error', 'warning:', 'deprecated',
            'directory listing', 'internal server error'
        ]
        
        content_lower = content.lower()
        for pattern in error_patterns:
            if pattern in content_lower:
                anomalies.append(pattern)
        
        return anomalies 