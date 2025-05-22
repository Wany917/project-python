"""
Module 3: Automatisation d'attaques web.

Ce module fournit des outils pour l'automatisation des tests de pénétration web,
y compris le fuzzing, les requêtes HTTP avancées et le contournement de CAPTCHA.
"""

__version__ = "0.1.0"

# Imports publics pour faciliter l'accès aux principales fonctionnalités
from module_3_web.core.fuzzer import WebFuzzer
from module_3_web.core.requester import WebRequester
from module_3_web.core.captcha_solver import CaptchaSolver 