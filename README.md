# 🔐 PasswordCheck

> *Because "password123" is still someone's idea of Fort Knox.*
>
> A **Password Vulnerability Detector** that checks your password against a comprehensive set of security rules and even queries the real-world [Have I Been Pwned](https://haveibeenpwned.com/) database to see if you got caught in someone else's mess.

---

## 📖 Table of Contents

- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage: CLI](#usage--cli)
- [Usage: Web App](#usage--web-app)
- [Security Checks Explained](#security-checks-explained)
- [Scoring System](#scoring-system)
- [CLI Flags Reference](#cli-flags-reference)
- [Guide en Français](#-guide-en-français)

---

## How It Works

PasswordCheck runs your password through like a dozen different checks, calculates entropy, estimates how long it'd take to crack, and queries the HIBP API to see if it showed up in any public data breaches. Then it gives you a score and tells you whether you're cooked or good to go.

The app has three main parts:

1. **`password_check.py`** - The core Python engine that does all the checking and spits out a report.
2. **`api.py`** - A lightweight Flask REST API that lets any client hit it over HTTP so you don't have to use the terminal if you don't want to.
3. **`frontend/`** - A React + Vite web interface that talks to the API so you can check passwords in your browser like a normal person.

---

## Installation

### Python engine & API

```bash
# Clone the repo
git clone https://github.com/Danjummah23/PasswordCheck.git
cd PasswordCheck

# Install dependencies
pip install flask flask-cors
```

### Frontend

```bash
cd frontend
npm install
```

---

## Usage: CLI

### Interactive mode (the normal way)

Just run it without any arguments and it'll ask you to type a password safely (it's hidden):

```bash
python password_check.py
```

### Direct mode

Pass the password as an argument (careful though, it might end up in your shell history, which is kinda ironic for a security tool):

```bash
python password_check.py "MyP@ssw0rd!
```

### Batch mode

Check a whole file of passwords at once and get a summary:

```bash
python password_check.py --batch passwords.txt
```

### Personal info mode

Give it your name, username, and birth year so it can warn you if your password is literally just your own info:

```bash
python password_check.py --personal
```

### JSON output

Get output you can actually use in other scripts or pipelines:

```bash
python password_check.py "MyP@ssw0rd!" --json
```

---

## Usage: Web App

1. Start the API server:
   ```bash
   python api.py
   ```
   The API will be at `http://localhost:5000`.

2. In another terminal, start the frontend dev server:
   ```bash
   cd frontend
   npm run dev
   ```

3. Open your browser and go to the URL Vite shows you (usually `http://localhost:5173`).

4. Type a password into the input field and get results instantly. No terminal required.

5. The frontend sends a `POST` request to `/api/check` with your password and shows you everything: score, entropy, crack time, all the individual check results, the whole deal.

---

## Security Checks Explained

| Check | What it looks for | Severity |
|---|---|---|
| **Length** | Passwords under 8 chars get rejected; under 12 is a warning | Critical / Warning |
| **Character variety** | Needs uppercase, lowercase, digits, and special characters mixed in | Critical / Warning |
| **Keyboard walk** | Catches sequences like `qwerty`, `asdfgh`, `12345` - yes, just mashing keyboard rows is apparently what passes for creativity to some people | Critical |
| **Repeated characters** | Flags patterns like `aaa` or `111` | Warning |
| **Sequential numbers** | Catches runs like `123`, `456` | Warning |
| **Date patterns** | Spots birth years, MMDD, DDMM, YYMMDD - because your birthday is definitely not common knowledge or anything | Warning |
| **Leet speak** | Sees through `p@ssw0rd` and `l3tm31n` - the hacker aesthetic that fools literally no one | Critical |
| **Dictionary words** | Matches against 150+ common words including names, brands, pop culture, sports, all that stuff | Warning |
| **Personal info** | Checks if your name, username, or birth year shows up in the password | Critical |
| **HIBP breach check** | Queries the Have I Been Pwned API (using k-anonymity model so only the first 5 chars of the SHA-1 hash get sent) | Critical |

### How the HIBP check keeps your data safe

Your actual password is never sent anywhere. The tool hashes it with SHA-1, sends only the first 5 characters of that hash to HIBP, and compares the rest server-side. It's pretty clever actually.

---

## Scoring System

The final score depends on how many critical issues and warnings your password has:

| Score | Condition |
|---|---|
| 🔴 **VERY WEAK** | 2 or more critical issues |
| 🔴 **WEAK** | Exactly 1 critical issue |
| 🟡 **FAIR** | 2 or more warnings, no critical issues |
| 🟢 **GOOD** | Exactly 1 warning, no critical issues |
| 🟢 **STRONG** | No critical issues and no warnings |

If you mess up somewhere, the tool also generates a strong password suggestion (18 characters, mixed case, digits and symbols) using Python's `secrets` module. So like, at least one of us is trying.

---

## CLI Flags Reference

| Flag | Description |
|---|---|
| `--no-hibp` | Skip the breach check if you want to go offline mode |
| `--show-password` | Print the password in the report output |
| `--personal` | Prompt for name, username, birth year to check against |
| `--json` | Output results as JSON |
| `--min-score LEVEL` | Exit with code 1 if the score is below LEVEL (useful in CI pipelines) |
| `--batch FILE` | Check every password in a text file |

---

# 🇫🇷 Guide en Français

> *Parce que "motdepasse123" reste la vision de Fort Knox pour certains.*
>
> PasswordCheck est un **détecteur de vulnérabilité de mot de passe** qui analyse votre mot de passe à travers une série de vérifications de sécurité et consulte la base de données réelle de Have I Been Pwned pour voir si vous avez été compromis.

---

## 📖 Table des matières

- [Fonctionnement général](#fonctionnement-général)
- [Installation](#installation-1)
- [Utilisation: CLI](#utilisation--cli)
- [Utilisation: Application Web](#utilisation--application-web)
- [Vérifications de sécurité](#vérifications-de-sécurité)
- [Système de score](#système-de-score)
- [Référence des options CLI](#référence-des-options-cli)

---

## Fonctionnement général

PasswordCheck analyse un mot de passe à travers plein de vérifications, calcule son entropie, estime le temps nécessaire pour le craquer, et interroge l'API HIBP pour vérifier s'il a été compromis.

L'application se compose de trois couches :

1. **`password_check.py`** - Le moteur Python principal qui exécute toutes les vérifications et génère un rapport.
2. **`api.py`** - Une API REST Flask légère qui expose le moteur via HTTP pour permettre à n'importe quel client de l'utiliser.
3. **`frontend/`** - Une interface web React + Vite qui communique avec l'API pour vous permettre de vérifier vos mots de passe depuis un navigateur, sans terminal.

---

## Installation

### Moteur Python et API

```bash
# Cloner le dépôt
git clone https://github.com/Danjummah23/PasswordCheck.git
cd PasswordCheck

# Installer les dépendances
pip install flask flask-cors
```

### Frontend

```bash
cd frontend
npm install
```

---

## Utilisation: CLI

### Mode interactif (la façon normale)

Lancez sans argument et l'outil vous demandera de saisir un mot de passe de façon sécurisée (la saisie est masquée) :

```bash
python password_check.py
```

### Mode direct

Passez le mot de passe directement en argument (attention, il peut apparaître dans l'historique de votre shell, ce qui est pas mal ironique pour un outil de sécurité) :

```bash
python password_check.py "MonM0tDePasse!"
```

### Mode batch

Vérifiez un fichier entier de mots de passe et obtenez un résumé :

```bash
python password_check.py --batch mots_de_passe.txt
```

### Mode informations personnelles

Fournissez votre nom, pseudo et année de naissance pour que l'outil vérifie si votre mot de passe n'est pas juste vos propres infos :

```bash
python password_check.py --personal
```

### Sortie JSON

Obtenez une sortie que vous pouvez utiliser dans des scripts ou des pipelines :

```bash
python password_check.py "MonM0tDePasse!" --json
```

---

## Utilisation: Application Web

1. Démarrez le serveur API :
   ```bash
   python api.py
   ```
   L'API sera à l'adresse `http://localhost:5000`.

2. Dans un autre terminal, démarrez le serveur de développement frontend :
   ```bash
   cd frontend
   npm run dev
   ```

3. Ouvrez votre navigateur et allez à l'URL affichée par Vite (généralement `http://localhost:5173`).

4. Saisissez un mot de passe et obtenez vos résultats instantanément, pas de terminal requis.

5. Le frontend envoie une requête `POST` à `/api/check` avec votre mot de passe et affiche le rapport complet : score, entropie, temps de craquage, résultats de chaque vérification, tout.

---

## Vérifications de sécurité

| Vérification | Ce qu'elle détecte | Sévérité |
|---|---|---|
| **Longueur** | Moins de 8 caractères c'est non; moins de 12 c'est un avertissement | Critique / Avertissement |
| **Variété de caractères** | Requiert un mélange de majuscules, minuscules, chiffres et caractères spéciaux | Critique / Avertissement |
| **Séquence clavier** | Détecte des séquences comme `qwerty`, `asdfgh`, `12345` - car juste appuyer sur les rangées du clavier n'est pas de la créativité | Critique |
| **Caractères répétés** | Signale des répétitions comme `aaa` ou `111` | Avertissement |
| **Nombres séquentiels** | Détecte des suites comme `123`, `456` | Avertissement |
| **Patterns de date** | Repère les années de naissance, formats MMJJ, JJMM, AAMMJJ - parce que votre date de naissance est tellement pas publique | Avertissement |
| **Leet speak** | Voit à travers `p@ssw0rd` et `l3tm31n` - l'esthétique hacker qui ne trompe absolument personne | Critique |
| **Mots du dictionnaire** | Correspond à plus de 150 mots courants incluant prénoms, marques, culture pop et sports | Avertissement |
| **Informations personnelles** | Vérifie si votre nom, pseudo ou année de naissance apparaît dans le mot de passe | Critique |
| **Vérification HIBP** | Interroge l'API Have I Been Pwned (modèle k-anonymat, seuls les 5 premiers caractères du hash SHA-1 sont envoyés) | Critique |

### Comment la vérification HIBP protège votre vie privée

Votre mot de passe réel n'est jamais envoyé nulle part. L'outil calcule le hash SHA-1 de votre mot de passe, envoie uniquement les 5 premiers caractères de ce hash à l'API HIBP, et compare le reste côté serveur. C'est assez malin en fait.

---

## Système de score

Le score final dépend du nombre de problèmes critiques et d'avertissements détectés :

| Score | Condition |
|---|---|
| 🔴 **VERY WEAK** | 2 problèmes critiques ou plus |
| 🔴 **WEAK** | Exactement 1 problème critique |
| 🟡 **FAIR** | 2 avertissements ou plus, aucun problème critique |
| 🟢 **GOOD** | Exactement 1 avertissement, aucun problème critique |
| 🟢 **STRONG** | Aucun problème critique, aucun avertissement |

Si vous avez des problèmes, l'outil génère également une suggestion de mot de passe robuste (18 caractères, majuscules/minuscules, chiffres et symboles) via le module Python `secrets`. Au moins quelqu'un essaie.

---

## Référence des options CLI

| Option | Description |
|---|---|
| `--no-hibp` | Ignorer la vérification de fuite si vous voulez mode hors ligne |
| `--show-password` | Afficher le mot de passe dans le rapport |
| `--personal` | Demander le nom, pseudo et année de naissance à vérifier |
| `--json` | Afficher les résultats en JSON |
| `--min-score NIVEAU` | Quitter avec le code 1 si le score est inférieur au NIVEAU (utile dans les pipelines CI) |
| `--batch FICHIER` | Vérifier chaque mot de passe dans un fichier texte |

---

*Made with ❤️ and a hint of shame for every "password123" still out there.*
