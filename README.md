# IDS/IPS & Analyse Shellcode Python (Scapy, Capstone, Unicorn)

## Description
Ce projet implémente un système de détection et de prévention d'intrusion (IDS/IPS) en utilisant la bibliothèque Scapy de Python. L'outil est capable d'analyser le trafic réseau en temps réel, de détecter les tentatives d'attaques et de générer des rapports détaillés.

### **Nouveau : Module 2 (en développement)**
Le projet s'enrichit d'un **Module 2** dédié à l'analyse de shellcodes, au désassemblage et à l'émulation de code malveillant. Ce module vise à :
- Charger et analyser des shellcodes (statique et dynamique)
- Désassembler le code binaire (avec Capstone)
- Émuler l'exécution de shellcodes (avec Unicorn)
- Générer des rapports d'analyse détaillés

> **Statut :** Le module 2 est en cours de développement. Suivez les mises à jour dans le dossier `src/module_2_shellcode/`.

## Fonctionnalités
- Capture de paquets réseau sur une interface spécifique
- Analyse des protocoles réseau reçus sur la carte
- Génération de rapports PDF avec graphiques et tableaux des protocoles détectés
- Détection et signalement de trafic illégitime (injection SQL, ARP Spoofing, etc.)
- Blocage optionnel des machines attaquantes
- **(À venir)** Analyse de shellcode, désassemblage, émulation, rapport d'analyse (Module 2)

## Prérequis
- Python 3.10 ou supérieur
- Poetry pour la gestion des dépendances
- Scapy pour l'analyse de trafic
- PyGal pour la génération de graphiques
- FPDF pour la génération de rapports PDF
- Capstone, Unicorn, Pwntools (pour le module 2)

## Installation

1. Cloner le dépôt :
```bash
git clone [URL_DU_DEPOT]
cd module-1-scapy
```

2. Installer les dépendances avec Poetry :
```bash
poetry install
```

## Utilisation

### Lancer l'outil de détection (Module 1) :
```bash
poetry run python -m module_1_scapy.main --interface eth0
```

### (À venir) Lancer l'analyse de shellcode (Module 2) :
```bash
poetry run python -m module_2_shellcode.main --help
```

### Options disponibles Module 1 :
- `--interface` : Interface réseau à analyser (obligatoire)
- `--output` : Chemin du fichier de rapport à générer (défaut: `report.pdf`)
- `--timeout` : Durée de la capture en secondes (défaut: 60)
- `--block` : Activer le blocage automatique des attaquants (optionnel)

## Structure du projet
Voir le fichier [CONVENTIONS.md](CONVENTIONS.md) pour plus de détails sur la structure du projet et les conventions de code.

## Développement

### Installation de l'environnement de développement :
```bash
poetry install --with dev
pre-commit install
```

### Exécuter les tests :
```bash
poetry run pytest
```

## Contributeurs
- [Nom du contributeur 1]
- [Nom du contributeur 2]

## Licence
Ce projet est distribué sous licence [LICENCE]. Voir le fichier LICENSE pour plus de détails.

# Projet Sécurité Python

Ce projet contient différents modules liés à la sécurité Python :

1. **Module 1** - IDS/IPS avec Scapy : Système de détection et prévention d'intrusion basé sur Scapy
2. **Module 2** - Analyse de Shellcode : Analyseur de shellcode avancé avec Pylibemu
3. **Module 3** - Attaques Web : Automatisation d'attaques web avec Requests et résolution de CAPTCHA

## Installation

Assurez-vous d'avoir Python 3.8+ installé.

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/yourusername/module-1-scapy.git
   cd module-1-scapy
   ```

2. Installer les dépendances avec Poetry :
   ```bash
   poetry install
   ```

3. Activer l'environnement virtuel :
   ```bash
   poetry shell
   ```

## Structure du projet

Le projet est organisé en trois modules principaux :

```
module-1-scapy/
├── src/
│   ├── module_1_scapy/     # Module 1 - IDS/IPS avec Scapy
│   ├── module_2_shellcode/ # Module 2 - Analyse de Shellcode
│   └── module_3_web/       # Module 3 - Automatisation d'attaques web
├── tests/                  # Tests unitaires
├── pyproject.toml          # Configuration du projet
└── README.md               # Documentation
```

## Module 1 - IDS/IPS avec Scapy

Ce module implémente un système de détection et prévention d'intrusion réseau.

### Fonctionnalités

- Capture de trafic réseau en temps réel
- Analyse de paquets et détection d'attaques
- Filtrage et blocage de paquets malveillants
- Génération de rapports

### Utilisation

```bash
# Lancer l'IDS en mode détection
poetry run ids --interface eth0

# Lancer l'IDS en mode prévention
poetry run ids --interface eth0 --prevent

# Générer un rapport
poetry run ids --interface eth0 --output report.pdf
```

## Module 2 - Analyse de Shellcode

Ce module permet d'analyser du shellcode avec Pylibemu pour détecter les comportements malveillants.

### Fonctionnalités

- Analyse statique de shellcode
- Émulation de shellcode pour détecter les comportements malveillants
- Détection des techniques d'obfuscation
- Génération de rapports d'analyse

### Utilisation

```bash
# Analyser un fichier contenant du shellcode
poetry run analyze-shellcode --file shellcode.bin

# Analyser du shellcode depuis une chaîne hexadécimale
poetry run analyze-shellcode --hex "\x90\x90\x90\xeb\x1e"
```

## Module 3 - Automatisation d'attaques web

Ce module fournit des outils pour automatiser les tests de pénétration web.

### Fonctionnalités

- Fuzzing d'applications web
- Automatisation de requêtes HTTP complexes
- Résolution de CAPTCHA
- Génération de rapports

### Utilisation

```bash
# Effectuer du fuzzing sur une application web
poetry run webattack fuzz --url https://exemple.com --wordlist wordlist.txt

# Crawler un site web
poetry run webattack crawl --url https://exemple.com --depth 3

# Résoudre un CAPTCHA
poetry run webattack captcha --image captcha.png
```

## Développement

### Tests

Pour exécuter les tests unitaires :

```bash
poetry run pytest
```

### Linting

Pour vérifier le code avec pylint :

```bash
poetry run pylint src tests
```

## Licence

Ce projet est sous licence MIT.
