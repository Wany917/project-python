# Conventions de Code - Projet IDS/IPS avec Scapy

## Structure du Projet

```
module-1-scapy/
├── src/                       # Code source du projet
│   └── module_1_scapy/        # Package principal
│       ├── __init__.py        # Initialisation du package
│       ├── capture.py         # Module de capture de trafic
│       ├── analyzer.py        # Module d'analyse des protocoles
│       ├── detection.py       # Module de détection d'attaques
│       ├── reporter.py        # Module de génération de rapports
│       └── utils.py           # Utilitaires divers
├── tests/                     # Tests unitaires
│   └── module_1_scapy/
│       ├── test_capture.py    # Tests pour capture.py
│       ├── test_analyzer.py   # Tests pour analyzer.py
│       ├── test_detection.py  # Tests pour detection.py
│       └── test_reporter.py   # Tests pour reporter.py
├── pyproject.toml            # Configuration du projet Poetry
├── README.md                 # Documentation principale
├── CONVENTIONS.md            # Ce fichier de conventions
└── .pre-commit-config.yaml   # Configuration pre-commit
```

## Conventions de Nommage

### Variables et Fonctions

- Noms en minuscules avec underscore (snake_case)
- Exemples: `capture_packets()`, `analyze_protocol()`

### Classes

- Noms en CamelCase
- Exemples: `PacketCapture`, `ProtocolAnalyzer`

### Constantes

- Noms en majuscules avec underscore
- Exemples: `MAX_PACKETS`, `DEFAULT_TIMEOUT`

## Style de Code

### Général

- Utiliser des noms explicites pour les variables et fonctions
- Limiter les fonctions à 15 lignes maximum (1 fonction = 1 action)
- Utiliser `logger` au lieu de `print` pour les logs

### Documentation

- Chaque fonction doit avoir une docstring décrivant:
  - Sa fonction
  - Ses paramètres
  - Son retour
- Format des docstrings:

```python
def function_name(param1, param2):
    """Description de la fonction.
    
    Args:
        param1: Description du premier paramètre
        param2: Description du second paramètre
        
    Returns:
        Description de ce que la fonction retourne
    """
```

### Tests

- Suivre le format: Given/When/Then
- Nommer les tests de manière descriptive: `test_nom_explicite_du_test()`

## Gestion des Dépendances

- Utiliser Poetry pour gérer les dépendances
- Toujours spécifier la version des dépendances

## Logging

- Utiliser le module `logging` standard de Python
- Niveaux de log appropriés:
  - DEBUG: Informations détaillées de développement
  - INFO: Confirmation d'opérations normales
  - WARNING: Situations inattendues mais gérables
  - ERROR: Erreurs empêchant une fonctionnalité de fonctionner
  - CRITICAL: Erreurs empêchant l'application de fonctionner

## Contrôle de Version

- Commits atomiques (une seule responsabilité par commit)
- Messages de commit descriptifs et concis
- Format: `[TYPE] Description du changement`
  - Types: FEAT, FIX, DOCS, STYLE, REFACTOR, TEST, CHORE
