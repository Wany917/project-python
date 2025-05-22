"""
Point d'entrée principal du module d'automatisation d'attaques web.

Ce module fournit une interface en ligne de commande pour les
fonctionnalités d'automatisation d'attaques web.
"""

import argparse
import logging
import os
import sys
import time
from typing import Dict, List, Any, Optional

from module_3_web.core.fuzzer import WebFuzzer
from module_3_web.core.requester import WebRequester
from module_3_web.core.captcha_solver import CaptchaSolver
from module_3_web.core.auth import WebAuthenticator
from module_3_web.reporting.reporter import WebReporter
from module_3_web.utils.tools import load_wordlist, extract_links
from module_3_web.utils.validation import is_valid_url

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parse les arguments de ligne de commande.
    
    Returns:
        Espace de noms contenant les arguments analysés
    """
    parser = argparse.ArgumentParser(
        description="Module d'automatisation d'attaques web"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commande à exécuter")
    
    # Sous-commande pour le fuzzing
    fuzzer_parser = subparsers.add_parser("fuzz", help="Effectuer du fuzzing sur une application web")
    fuzzer_parser.add_argument("--url", required=True, help="URL cible")
    fuzzer_parser.add_argument("--wordlist", required=True, help="Chemin vers la wordlist")
    fuzzer_parser.add_argument("--extensions", nargs='+', default=None, help="Extensions à tester (ex: .php .html)")
    fuzzer_parser.add_argument("--threads", type=int, default=10, help="Nombre de threads")
    fuzzer_parser.add_argument("--timeout", type=int, default=10, help="Timeout en secondes")
    fuzzer_parser.add_argument("--output", default=None, help="Chemin du rapport de sortie")
    
    # Sous-commande pour le crawler
    crawler_parser = subparsers.add_parser("crawl", help="Crawler un site web")
    crawler_parser.add_argument("--url", required=True, help="URL de départ")
    crawler_parser.add_argument("--depth", type=int, default=2, help="Profondeur maximale")
    crawler_parser.add_argument("--max-urls", type=int, default=100, help="Nombre maximal d'URLs")
    crawler_parser.add_argument("--output", default=None, help="Fichier de sortie")
    
    # Sous-commande pour la résolution de CAPTCHA
    captcha_parser = subparsers.add_parser("captcha", help="Résoudre un CAPTCHA")
    captcha_parser.add_argument("--image", required=True, help="Chemin ou URL de l'image CAPTCHA")
    captcha_parser.add_argument("--tesseract", default=None, help="Chemin vers l'exécutable Tesseract")
    captcha_parser.add_argument("--preprocess", action="store_true", help="Prétraiter l'image")
    captcha_parser.add_argument("--save-processed", default=None, help="Sauvegarder l'image prétraitée")
    
    # Sous-commande pour l'authentification
    auth_parser = subparsers.add_parser("auth", help="Authentification sur un site web")
    auth_parser.add_argument("--url", required=True, help="URL de la page d'authentification")
    auth_parser.add_argument("--username", required=True, help="Nom d'utilisateur")
    auth_parser.add_argument("--password", required=True, help="Mot de passe")
    auth_parser.add_argument("--captcha", action="store_true", help="Activer la résolution de captcha")
    auth_parser.add_argument("--captcha-selector", default="img.captcha", help="Sélecteur CSS pour l'image captcha")
    auth_parser.add_argument("--captcha-field", default="captcha", help="Nom du champ pour la valeur du captcha")
    auth_parser.add_argument("--form-id", default=None, help="ID du formulaire à utiliser")
    auth_parser.add_argument("--test", action="store_true", help="Mode test (simule une connexion)")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    if args.command in ["fuzz", "crawl", "auth"] and not is_valid_url(args.url):
        parser.error(f"URL invalide: {args.url}")
    
    return args


def run_fuzzer(args: argparse.Namespace) -> int:
    """
    Exécute le fuzzer web.
    
    Args:
        args: Arguments de ligne de commande
        
    Returns:
        Code de sortie (0 = succès)
    """
    try:
        logger.info(f"Démarrage du fuzzing sur {args.url}")
        
        extensions = args.extensions if args.extensions else ['', '.php', '.html', '.js', '.txt']
        
        fuzzer = WebFuzzer(
            base_url=args.url,
            max_threads=args.threads,
            timeout=args.timeout
        )
        
        start_time = time.time()
        results = fuzzer.fuzz_paths(args.wordlist, extensions)
        duration = time.time() - start_time
        
        logger.info(f"Fuzzing terminé en {duration:.2f}s, {len(results)} résultats trouvés")
        
        # Génération du rapport
        if results:
            reporter = WebReporter()
            report_path = reporter.generate_fuzzing_report(
                results=results,
                target_url=args.url,
                report_name=args.output
            )
            
            if report_path:
                logger.info(f"Rapport généré: {os.path.abspath(report_path)}")
                print(f"\nRapport généré avec succès: {os.path.abspath(report_path)}")
        else:
            logger.warning("Aucun résultat trouvé")
        
        return 0
    
    except Exception as e:
        logger.error(f"Erreur lors du fuzzing: {str(e)}", exc_info=True)
        return 1


def run_crawler(args: argparse.Namespace) -> int:
    """
    Exécute le crawler web.
    
    Args:
        args: Arguments de ligne de commande
        
    Returns:
        Code de sortie (0 = succès)
    """
    try:
        logger.info(f"Démarrage du crawling sur {args.url}")
        
        requester = WebRequester()
        
        visited_urls = set()
        queue = [(args.url, 0)]
        # Résultats (URL -> infos)
        results = {}
        
        logger.info(f"Crawling en cours (profondeur max: {args.depth}, max URLs: {args.max_urls})...")
        
        while queue and len(visited_urls) < args.max_urls:
            current_url, depth = queue.pop(0)
            
            if current_url in visited_urls or depth > args.depth:
                continue
            
            logger.info(f"Visite de {current_url} (profondeur {depth}/{args.depth})")
            
            try:
                response = requester.get(current_url)
                visited_urls.add(current_url)
                
                results[current_url] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'depth': depth
                }
                
                if depth < args.depth:
                    links = extract_links(response.text, current_url)
                    
                    for link in links:
                        if link not in visited_urls:
                            queue.append((link, depth + 1))
            
            except Exception as e:
                logger.warning(f"Erreur lors de la visite de {current_url}: {str(e)}")
        
        logger.info(f"Crawling terminé, {len(visited_urls)} URLs visitées")
        
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for url, info in results.items():
                        f.write(f"{url}\t{info['status_code']}\t{info['content_length']}\t{info['depth']}\n")
                
                logger.info(f"Résultats sauvegardés dans {args.output}")
                print(f"\nRésultats sauvegardés avec succès dans {os.path.abspath(args.output)}")
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde des résultats: {str(e)}")
        
        return 0
    
    except Exception as e:
        logger.error(f"Erreur lors du crawling: {str(e)}", exc_info=True)
        return 1


def run_captcha_solver(args: argparse.Namespace) -> int:
    """
    Exécute le solveur de CAPTCHA.
    
    Args:
        args: Arguments de ligne de commande
        
    Returns:
        Code de sortie (0 = succès)
    """
    try:
        logger.info("Initialisation du solveur de CAPTCHA")
        
        solver = CaptchaSolver(
            tesseract_cmd=args.tesseract,
            preprocess=args.preprocess
        )
        
        is_url = args.image.startswith(('http://', 'https://'))
        
        if is_url:
            logger.info(f"Résolution du CAPTCHA depuis l'URL: {args.image}")
            result = solver.solve_from_url(args.image)
        else:
            logger.info(f"Résolution du CAPTCHA depuis le fichier: {args.image}")
            result = solver.solve_from_file(args.image)
        
        if args.save_processed:
            if is_url:
                import requests
                from io import BytesIO
                response = requests.get(args.image)
                image_data = BytesIO(response.content)
                solver.save_preprocessed(image_data, args.save_processed)
            else:
                solver.save_preprocessed(args.image, args.save_processed)
            
            logger.info(f"Image prétraitée sauvegardée: {args.save_processed}")
        
        if result:
            logger.info(f"CAPTCHA résolu: {result}")
            print(f"CAPTCHA résolu: {result}")
        else:
            logger.warning("Échec de la résolution du CAPTCHA")
            print("Échec de la résolution du CAPTCHA")
        
        return 0
    
    except Exception as e:
        logger.error(f"Erreur lors de la résolution du CAPTCHA: {str(e)}", exc_info=True)
        return 1


def run_auth(args: argparse.Namespace) -> int:
    """
    Exécute l'authentification sur un site web.
    
    Args:
        args: Arguments de ligne de commande
        
    Returns:
        Code de sortie (0 = succès)
    """
    try:
        logger.info(f"Tentative d'authentification sur {args.url}")
        
        # Création de l'authentificateur
        auth = WebAuthenticator(args.url)
        
        # Mode test (simulation)
        if args.test:
            logger.info("Mode test activé (simulation)")
            success = auth.test_captcha_login(args.username, args.password)
        else:
            # Préparation des identifiants
            credentials = {"username": args.username, "password": args.password}
            
            # Préparation de l'identifiant du formulaire (si spécifié)
            form_identifier = {"id": args.form_id} if args.form_id else None
            
            # Authentification avec ou sans captcha
            if args.captcha:
                logger.info("Tentative d'authentification avec résolution de captcha")
                success = auth.login_with_captcha(
                    args.url,
                    credentials,
                    captcha_img_selector=args.captcha_selector,
                    captcha_field=args.captcha_field,
                    form_identifier=form_identifier
                )
            else:
                logger.info("Tentative d'authentification standard")
                success = auth.login(
                    args.url,
                    credentials,
                    form_identifier=form_identifier
                )
        
        if success:
            logger.info("Authentification réussie")
            print("\nAuthentification réussie!")
        else:
            logger.warning("Échec de l'authentification")
            print("\nÉchec de l'authentification.")
        
        return 0 if success else 1
    
    except Exception as e:
        logger.error(f"Erreur lors de l'authentification: {str(e)}", exc_info=True)
        return 1


def main() -> int:
    """
    Fonction principale.
    
    Returns:
        Code de sortie (0 = succès)
    """
    args = parse_arguments()
    
    if args.command == "fuzz":
        return run_fuzzer(args)
    elif args.command == "crawl":
        return run_crawler(args)
    elif args.command == "captcha":
        return run_captcha_solver(args)
    elif args.command == "auth":
        return run_auth(args)
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main()) 