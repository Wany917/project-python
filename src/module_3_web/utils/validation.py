"""
Fonctions de validation pour les opérations web.

Ce module fournit des fonctions pour valider différents
éléments comme les URLs, les paramètres, etc.
"""

import re
import logging
import ipaddress
from typing import List, Dict, Any, Union, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def is_valid_url(url: str) -> bool:
    """
    Vérifie si une URL est valide.
    
    Args:
        url: URL à vérifier
        
    Returns:
        True si l'URL est valide, False sinon
    """
    if not url:
        return False
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False


def is_valid_ip(ip: str) -> bool:
    """
    Vérifie si une adresse IP est valide.
    
    Args:
        ip: Adresse IP à vérifier
        
    Returns:
        True si l'adresse IP est valide, False sinon
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Vérifie si un nom de domaine est valide.
    
    Args:
        domain: Nom de domaine à vérifier
        
    Returns:
        True si le nom de domaine est valide, False sinon
    """
    if not domain:
        return False
    
    # Regex simplifiée pour les noms de domaine
    pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    return bool(pattern.match(domain))


def is_valid_email(email: str) -> bool:
    """
    Vérifie si une adresse email est valide.
    
    Args:
        email: Adresse email à vérifier
        
    Returns:
        True si l'adresse email est valide, False sinon
    """
    if not email:
        return False
    
    # Regex simplifiée pour les adresses email
    pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    return bool(pattern.match(email))


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Vérifie si un numéro de port est valide.
    
    Args:
        port: Numéro de port à vérifier
        
    Returns:
        True si le port est valide, False sinon
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_potentially_dangerous(input_str: str) -> bool:
    """
    Vérifie si une chaîne contient potentiellement du code malveillant.
    
    Args:
        input_str: Chaîne à vérifier
        
    Returns:
        True si la chaîne est potentiellement dangereuse, False sinon
    """
    if not input_str:
        return False
    
    # Patterns pour détecter des charges utiles potentiellement malveillantes
    patterns = [
        # Injection SQL
        r"['\"]\s*or\s+['\"0-9a-zA-Z]+=\s*['\"0-9a-zA-Z]+",
        r"--\s*$",
        r";\s*drop\s+table",
        r"union\s+select",
        
        # Cross-Site Scripting (XSS)
        r"<script.*?>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onmouseover=",
        r"onclick=",
        
        # Inclusion de fichiers
        r"\.\./",
        r"file:",
        
        # Commandes systèmes
        r";\s*ls\s+",
        r";\s*cat\s+",
        r";\s*rm\s+",
        r"&\s*[a-zA-Z0-9_-]+\s*&",
        r"\|\s*[a-zA-Z0-9_-]+",
    ]
    
    for pattern in patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True
    
    return False


def sanitize_url_path(path: str) -> str:
    """
    Sanitize un chemin d'URL.
    
    Args:
        path: Chemin à sanitizer
        
    Returns:
        Chemin sanitizé
    """
    if not path:
        return ""
    
    # Supprimer les caractères suspects
    sanitized = re.sub(r'[^a-zA-Z0-9_\-./]', '', path)
    
    # Supprimer les tentatives de traversée de répertoire
    sanitized = re.sub(r'\.\.[/\\]', '', sanitized)
    
    return sanitized


def validate_form_data(data: Dict[str, Any], required_fields: List[str] = None,
                     max_length: int = 1000) -> Dict[str, List[str]]:
    """
    Valide les données d'un formulaire.
    
    Args:
        data: Données à valider
        required_fields: Liste des champs obligatoires
        max_length: Longueur maximale des valeurs
        
    Returns:
        Dictionnaire des erreurs (vide si pas d'erreur)
    """
    errors = {}
    
    if required_fields:
        for field in required_fields:
            if field not in data or not data[field]:
                if 'missing_fields' not in errors:
                    errors['missing_fields'] = []
                errors['missing_fields'].append(field)
    
    for key, value in data.items():
        if isinstance(value, str):
            if len(value) > max_length:
                if 'too_long' not in errors:
                    errors['too_long'] = []
                errors['too_long'].append(key)
            
            if is_potentially_dangerous(value):
                if 'dangerous' not in errors:
                    errors['dangerous'] = []
                errors['dangerous'].append(key)
    
    return errors 