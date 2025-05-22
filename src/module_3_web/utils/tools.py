"""
Outils généraux pour les opérations web.

Ce module fournit des fonctions utilitaires diverses pour
les opérations web et le traitement des données.
"""

import os
import re
import json
import random
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_user_agents() -> List[str]:
    """
    Retourne une liste d'User-Agents courants.
    
    Returns:
        Liste de chaînes d'User-Agent
    """
    return [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    ]


def load_wordlist(file_path: str) -> List[str]:
    """
    Charge une wordlist depuis un fichier.
    
    Args:
        file_path: Chemin vers le fichier de wordlist
        
    Returns:
        Liste de mots
    """
    if not os.path.isfile(file_path):
        logger.error(f"Fichier de wordlist introuvable: {file_path}")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Wordlist chargée: {len(words)} mots depuis {file_path}")
        return words
    
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la wordlist: {str(e)}")
        return []


def extract_forms(html_content: str) -> List[Dict[str, Any]]:
    """
    Extrait les formulaires d'une page HTML.
    
    Args:
        html_content: Contenu HTML à analyser
        
    Returns:
        Liste de dictionnaires décrivant les formulaires
    """
    forms = []
    
    # Regex pour capturer les formulaires (approche simplifiée)
    form_pattern = re.compile(r'<form\s+([^>]*)>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    field_pattern = re.compile(r'<input\s+([^>]*)>', re.DOTALL | re.IGNORECASE)
    
    # Extraction des attributs
    def extract_attrs(attrs_str: str) -> Dict[str, str]:
        attrs = {}
        attr_pattern = re.compile(r'(\w+)=["\']([^"\']*)["\']', re.IGNORECASE)
        for match in attr_pattern.finditer(attrs_str):
            attrs[match.group(1).lower()] = match.group(2)
        return attrs
    
    # Recherche des formulaires
    for form_match in form_pattern.finditer(html_content):
        form_attrs = extract_attrs(form_match.group(1))
        form_content = form_match.group(2)
        
        # Informations de base du formulaire
        form_info = {
            'action': form_attrs.get('action', ''),
            'method': form_attrs.get('method', 'get'),
            'id': form_attrs.get('id', ''),
            'name': form_attrs.get('name', ''),
            'fields': []
        }
        
        # Extraction des champs
        for field_match in field_pattern.finditer(form_content):
            field_attrs = extract_attrs(field_match.group(1))
            
            # Ignorer les champs sans nom
            if 'name' not in field_attrs:
                continue
            
            form_info['fields'].append({
                'name': field_attrs.get('name', ''),
                'type': field_attrs.get('type', 'text'),
                'value': field_attrs.get('value', ''),
                'required': 'required' in field_attrs
            })
        
        forms.append(form_info)
    
    logger.info(f"Formulaires extraits: {len(forms)}")
    return forms


def extract_links(html_content: str, base_url: str = None) -> List[str]:
    """
    Extrait les liens d'une page HTML.
    
    Args:
        html_content: Contenu HTML à analyser
        base_url: URL de base pour les liens relatifs
        
    Returns:
        Liste de liens absolus
    """
    links = []
    
    # Regex pour capturer les liens
    link_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
    
    # Extraction des liens
    for link_match in link_pattern.finditer(html_content):
        link = link_match.group(1).strip()
        
        # Ignorer les ancres et les liens JavaScript
        if link.startswith('#') or link.startswith('javascript:'):
            continue
        
        # Convertir les liens relatifs en absolus si un base_url est fourni
        if base_url and not link.startswith(('http://', 'https://')):
            if link.startswith('/'):
                # Lien absolu par rapport au domaine
                parsed_base = urlparse(base_url)
                link = f"{parsed_base.scheme}://{parsed_base.netloc}{link}"
            else:
                # Lien relatif
                link = f"{base_url.rstrip('/')}/{link}"
        
        links.append(link)
    
    # Éliminer les doublons
    unique_links = list(set(links))
    
    logger.info(f"Liens extraits: {len(unique_links)}")
    return unique_links


def generate_random_params(param_names: List[str], values: List[str] = None) -> Dict[str, str]:
    """
    Génère des paramètres aléatoires pour les tests.
    
    Args:
        param_names: Liste des noms de paramètres
        values: Liste des valeurs possibles (optionnel)
        
    Returns:
        Dictionnaire de paramètres
    """
    if not values:
        values = [
            "test", "1", "true", "false", "admin", "user", "password",
            "' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd"
        ]
    
    params = {}
    for param in param_names:
        params[param] = random.choice(values)
    
    return params


def parse_robots_txt(content: str) -> Dict[str, Any]:
    """
    Parse un fichier robots.txt.
    
    Args:
        content: Contenu du fichier robots.txt
        
    Returns:
        Dictionnaire des règles extraites
    """
    rules = {
        'disallow': [],
        'allow': [],
        'sitemaps': [],
        'user_agents': {}
    }
    
    current_agent = "*"
    
    for line in content.splitlines():
        line = line.strip()
        
        # Ignorer les commentaires et lignes vides
        if not line or line.startswith('#'):
            continue
        
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
        
        directive = parts[0].strip().lower()
        value = parts[1].strip()
        
        if directive == 'user-agent':
            current_agent = value
            if current_agent not in rules['user_agents']:
                rules['user_agents'][current_agent] = {'disallow': [], 'allow': []}
        
        elif directive == 'disallow':
            if value:
                if current_agent == "*":
                    rules['disallow'].append(value)
                else:
                    rules['user_agents'][current_agent]['disallow'].append(value)
        
        elif directive == 'allow':
            if value:
                if current_agent == "*":
                    rules['allow'].append(value)
                else:
                    rules['user_agents'][current_agent]['allow'].append(value)
        
        elif directive == 'sitemap':
            if value:
                rules['sitemaps'].append(value)
    
    return rules 