"""
Module pour l'envoi de requêtes HTTP avancées.

Ce module fournit des outils pour automatiser les requêtes HTTP
avec gestion des sessions, des cookies, des formulaires, etc.
"""

import logging
import json
import time
from typing import Dict, List, Union, Optional, Any, Tuple, Callable
import requests
from requests.exceptions import RequestException

from module_3_web.utils.tools import get_user_agents, extract_forms
from module_3_web.utils.validation import is_valid_url

logger = logging.getLogger(__name__)


class WebRequester:
    """
    Classe pour effectuer des requêtes HTTP avancées.
    
    Cette classe permet d'automatiser les requêtes HTTP avec gestion
    des sessions, cookies, formulaires, et analyse des réponses.
    """
    
    def __init__(self, base_url: str = None, timeout: int = 10, auto_cookies: bool = True):
        """
        Initialise un nouveau requester web.
        
        Args:
            base_url: URL de base pour les requêtes (optionnel)
            timeout: Timeout pour les requêtes en secondes
            auto_cookies: Activer la gestion automatique des cookies
        """
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.user_agents = get_user_agents()
        self.history: List[Dict[str, Any]] = []
        
        if base_url and not is_valid_url(base_url):
            logger.warning(f"URL de base potentiellement invalide: {base_url}")
        
        # Paramètres de session
        if not auto_cookies:
            self.session.cookies.clear()
        
        logger.info(f"WebRequester initialisé" + (f" pour {base_url}" if base_url else ""))
    
    def get(self, url: str, params: Dict[str, Any] = None, headers: Dict[str, str] = None,
            follow_redirects: bool = True) -> requests.Response:
        """
        Effectue une requête GET.
        
        Args:
            url: URL à requêter (relative ou absolue)
            params: Paramètres de l'URL
            headers: En-têtes HTTP
            follow_redirects: Suivre les redirections
            
        Returns:
            Objet Response
        """
        full_url = self._build_url(url)
        _headers = self._prepare_headers(headers)
        
        try:
            start_time = time.time()
            response = self.session.get(
                full_url,
                params=params,
                headers=_headers,
                timeout=self.timeout,
                allow_redirects=follow_redirects
            )
            duration = time.time() - start_time
            
            self._log_request("GET", full_url, response, duration)
            self._save_history("GET", full_url, params, None, response)
            
            return response
        
        except RequestException as e:
            logger.error(f"Erreur lors de la requête GET vers {full_url}: {str(e)}")
            raise
    
    def post(self, url: str, data: Dict[str, Any] = None, json_data: Dict[str, Any] = None,
             headers: Dict[str, str] = None, files: Dict[str, Any] = None,
             follow_redirects: bool = True) -> requests.Response:
        """
        Effectue une requête POST.
        
        Args:
            url: URL à requêter (relative ou absolue)
            data: Données de formulaire
            json_data: Données JSON
            headers: En-têtes HTTP
            files: Fichiers à envoyer
            follow_redirects: Suivre les redirections
            
        Returns:
            Objet Response
        """
        full_url = self._build_url(url)
        _headers = self._prepare_headers(headers)
        
        if json_data:
            _headers.update({'Content-Type': 'application/json'})
        
        try:
            start_time = time.time()
            response = self.session.post(
                full_url,
                data=data,
                json=json_data,
                headers=_headers,
                files=files,
                timeout=self.timeout,
                allow_redirects=follow_redirects
            )
            duration = time.time() - start_time
            
            self._log_request("POST", full_url, response, duration)
            self._save_history("POST", full_url, None, data or json_data, response)
            
            return response
        
        except RequestException as e:
            logger.error(f"Erreur lors de la requête POST vers {full_url}: {str(e)}")
            raise
    
    def submit_form(self, url: str, form_data: Dict[str, str], form_id: str = None,
                   headers: Dict[str, str] = None) -> requests.Response:
        """
        Soumet un formulaire HTML.
        
        Args:
            url: URL contenant le formulaire
            form_data: Données à soumettre
            form_id: ID du formulaire (optionnel)
            headers: En-têtes HTTP
            
        Returns:
            Objet Response
            
        Raises:
            ValueError: Si le formulaire n'est pas trouvé
        """
        # D'abord récupérer la page contenant le formulaire
        response = self.get(url, headers=headers)
        
        # Extraire les informations du formulaire
        forms = extract_forms(response.text)
        
        if not forms:
            raise ValueError(f"Aucun formulaire trouvé sur {url}")
        
        # Sélectionner le formulaire à soumettre
        target_form = None
        if form_id:
            for form in forms:
                if form.get('id') == form_id:
                    target_form = form
                    break
            
            if not target_form:
                raise ValueError(f"Formulaire avec ID '{form_id}' non trouvé")
        else:
            # Utiliser le premier formulaire par défaut
            target_form = forms[0]
        
        # Préparer les données du formulaire
        form_url = target_form.get('action', url)
        method = target_form.get('method', 'post').lower()
        
        # Compléter les données du formulaire avec les champs cachés
        full_form_data = {}
        for field in target_form.get('fields', []):
            if field.get('type') == 'hidden':
                full_form_data[field.get('name')] = field.get('value', '')
        
        # Ajouter les données fournies par l'utilisateur
        full_form_data.update(form_data)
        
        # Soumettre le formulaire
        if method == 'get':
            return self.get(form_url, params=full_form_data, headers=headers)
        else:
            return self.post(form_url, data=full_form_data, headers=headers)
    
    def navigate(self, url: str, steps: List[Dict[str, Any]]) -> List[requests.Response]:
        """
        Effectue une séquence de navigation (par exemple pour un login suivi d'actions).
        
        Args:
            url: URL de départ
            steps: Liste d'étapes à effectuer
            
        Returns:
            Liste des réponses obtenues
        """
        responses = []
        current_url = url
        
        for step in steps:
            action = step.get('action', 'get')
            data = step.get('data')
            params = step.get('params')
            headers = step.get('headers')
            wait = step.get('wait')
            
            if wait:
                time.sleep(wait)
            
            try:
                if action.lower() == 'get':
                    response = self.get(current_url, params=params, headers=headers)
                elif action.lower() == 'post':
                    response = self.post(current_url, data=data, headers=headers)
                elif action.lower() == 'form':
                    response = self.submit_form(current_url, data, form_id=step.get('form_id'), headers=headers)
                else:
                    logger.warning(f"Action non reconnue: {action}")
                    continue
                
                responses.append(response)
                
                # Mettre à jour l'URL pour la prochaine étape
                if step.get('follow_url') and response.headers.get('Location'):
                    current_url = response.headers.get('Location')
                elif step.get('next_url'):
                    current_url = step.get('next_url')
            
            except RequestException as e:
                logger.error(f"Erreur lors de l'étape {len(responses) + 1}: {str(e)}")
                break
        
        return responses
    
    def _build_url(self, url: str) -> str:
        """
        Construit une URL absolue.
        
        Args:
            url: URL relative ou absolue
            
        Returns:
            URL absolue
        """
        if url.startswith(('http://', 'https://')):
            return url
        elif self.base_url:
            return f"{self.base_url.rstrip('/')}/{url.lstrip('/')}"
        else:
            raise ValueError(f"URL relative '{url}' fournie sans URL de base")
    
    def _prepare_headers(self, headers: Dict[str, str] = None) -> Dict[str, str]:
        """
        Prépare les en-têtes pour une requête.
        
        Args:
            headers: En-têtes spécifiques à la requête
            
        Returns:
            En-têtes complets
        """
        default_headers = {
            'User-Agent': self.user_agents[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        
        if headers:
            default_headers.update(headers)
        
        return default_headers
    
    def _log_request(self, method: str, url: str, response: requests.Response, duration: float) -> None:
        """
        Enregistre les informations d'une requête dans les logs.
        
        Args:
            method: Méthode HTTP
            url: URL
            response: Réponse HTTP
            duration: Durée de la requête
        """
        logger.info(
            f"{method} {url} -> {response.status_code} "
            f"({len(response.content)} bytes en {duration:.2f}s)"
        )
    
    def _save_history(self, method: str, url: str, params: Dict[str, Any],
                     data: Dict[str, Any], response: requests.Response) -> None:
        """
        Sauvegarde une requête dans l'historique.
        
        Args:
            method: Méthode HTTP
            url: URL
            params: Paramètres GET
            data: Données POST
            response: Réponse HTTP
        """
        self.history.append({
            'method': method,
            'url': url,
            'params': params,
            'data': data,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'timestamp': time.time()
        })
        
        # Limiter la taille de l'historique
        if len(self.history) > 100:
            self.history.pop(0)
    
    def clear_session(self) -> None:
        """Efface la session (cookies, historique)."""
        self.session.cookies.clear()
        self.history.clear()
        logger.info("Session effacée")
    
    def get_cookies(self) -> Dict[str, str]:
        """
        Retourne les cookies actuels.
        
        Returns:
            Dictionnaire des cookies
        """
        return {cookie.name: cookie.value for cookie in self.session.cookies}
    
    def set_proxy(self, proxy: str) -> None:
        """
        Configure un proxy pour les requêtes.
        
        Args:
            proxy: URL du proxy (ex: "http://127.0.0.1:8080")
        """
        self.session.proxies = {
            'http': proxy,
            'https': proxy
        }
        logger.info(f"Proxy configuré: {proxy}")
    
    def export_history(self, format_type: str = 'json') -> str:
        """
        Exporte l'historique dans un format spécifié.
        
        Args:
            format_type: Format d'export ('json' ou 'csv')
            
        Returns:
            Chaîne formatée
        """
        if format_type == 'json':
            return json.dumps(self.history, indent=2)
        elif format_type == 'csv':
            csv_content = "method,url,status_code,content_length,timestamp\n"
            for entry in self.history:
                csv_content += (
                    f"{entry['method']},{entry['url']},{entry['status_code']},"
                    f"{entry['content_length']},{entry['timestamp']}\n"
                )
            return csv_content
        else:
            raise ValueError(f"Format non supporté: {format_type}")
        
    def download_file(self, url: str, destination: str) -> bool:
        """
        Télécharge un fichier depuis une URL.
        
        Args:
            url: URL du fichier à télécharger
            destination: Chemin de destination
            
        Returns:
            True si le téléchargement a réussi, False sinon
        """
        try:
            response = self.get(url, follow_redirects=True)
            
            with open(destination, 'wb') as f:
                f.write(response.content)
            
            logger.info(f"Fichier téléchargé avec succès: {destination}")
            return True
        
        except (RequestException, IOError) as e:
            logger.error(f"Erreur lors du téléchargement de {url}: {str(e)}")
            return False 