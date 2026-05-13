# 🔐 PasswordCheck

> *Because "password123" is still someone's idea of Fort Knox.*
>
> A **Password Vulnerability Detector** that checks your password against a comprehensive set of security rules and even queries the real-world [Have I Been Pwned](https://haveibeenpwned.com/) breach database — just to make sure your "super secure" password hasn't already been leaked a few thousand times.
>
> ---
>
> ## 📖 Table of Contents
>
> - [How It Works](#how-it-works)
> - - [Installation](#installation)
>   - - [Usage — CLI](#usage--cli)
>     - - [Usage — Web App](#usage--web-app)
>       - - [Security Checks Explained](#security-checks-explained)
>         - - [Scoring System](#scoring-system)
>           - - [CLI Flags Reference](#cli-flags-reference)
>            
>             - ---
>
> ## How It Works
>
> PasswordCheck analyses a password through a pipeline of checks, computes its entropy, estimates crack time, and queries the HIBP API to see if it has appeared in known data breaches. At the end it gives the password a score from **VERY WEAK** to **STRONG**, and — if needed — suggests a better one.
>
> The application has three layers:
>
> 1. **`password_check.py`** — The core Python engine that runs all checks and produces a report.
> 2. 2. **`api.py`** — A lightweight Flask REST API that exposes the engine over HTTP so any client can use it.
>    3. 3. **`frontend/`** — A React + Vite web interface that talks to the API so you can check passwords in your browser without touching a terminal.
>      
>       4. ---
>      
>       5. ## Installation
>      
>       6. ### Python engine & API
>
> ```bash
> # Clone the repo
> git clone https://github.com/Danjummah23/PasswordCheck.git
> cd PasswordCheck
>
> # Install dependencies
> pip install flask flask-cors
> ```
>
> ### Frontend
>
> ```bash
> cd frontend
> npm install
> ```
>
> ---
>
> ## Usage — CLI
>
> ### Interactive mode *(recommended for humans)*
>
> Run without arguments and the tool will prompt you to type a password securely (input is hidden):
>
> ```bash
> python password_check.py
> ```
>
> ### Direct mode
>
> Pass the password directly as an argument *(careful — it may appear in your shell history, which is peak irony for a security tool)*:
>
> ```bash
> python password_check.py "MyP@ssw0rd!"
> ```
>
> ### Batch mode
>
> Check an entire file of passwords at once and get a summary:
>
> ```bash
> python password_check.py --batch passwords.txt
> ```
>
> ### Personal-info mode
>
> Provide your name, username, and birth year so the tool can warn you if your password contains them:
>
> ```bash
> python password_check.py --personal
> ```
>
> ### JSON output
>
> Get machine-readable output for use in scripts or pipelines:
>
> ```bash
> python password_check.py "MyP@ssw0rd!" --json
> ```
>
> ---
>
> ## Usage — Web App
>
> 1. Start the API server:
> 2.  ```bash
>      python api.py
>      ```
>      The API will be available at `http://localhost:5000`.
>
> 2. In a separate terminal, start the frontend dev server:
> 3.  ```bash
>      cd frontend
>      npm run dev
>      ```
>
> 3. Open your browser and navigate to the URL shown by Vite (usually `http://localhost:5173`).
>
> 4. 4. Type a password into the input field and get your results instantly — no terminal required.
>   
>    5. The frontend sends a `POST` request to `/api/check` with your password and displays the full report including score, entropy, crack time, and individual check results.
>   
>    6. ---
>   
>    7. ## Security Checks Explained
>
>    8. | Check | What it looks for | Severity |
>    9. |---|---|---|
>    10. | **Length** | Passwords under 8 chars are rejected; under 12 is a warning | Critical / Warning |
>    11. | **Character variety** | Requires a mix of uppercase, lowercase, digits, and special chars | Critical / Warning |
>    12. | **Keyboard walk** | Detects sequences like `qwerty`, `asdfgh`, `12345` — yes, typing across the keyboard counts as creativity to exactly no one | Critical |
>    13. | **Repeated characters** | Flags patterns like `aaa` or `111` | Warning |
>    14. | **Sequential numbers** | Catches runs like `123`, `456` | Warning |
>    15. | **Date patterns** | Spots birth years, MMDD, DDMM, YYMMDD — because your birthday is not a secret | Warning |
>    16. | **Leet speak** | Sees through `p@ssw0rd` and `l3tm31n` — the hacker aesthetic that fools no one | Critical |
>    17. | **Dictionary words** | Matches against 150+ common words including names, brands, pop culture, and sports | Warning |
>    18. | **Personal info** | Checks if your name, username, or birth year appears in the password | Critical |
>    19. | **HIBP breach check** | Queries the Have I Been Pwned API (k-anonymity model — only the first 5 chars of the SHA-1 hash are sent) | Critical |
>
>    20. ### How the HIBP check protects your privacy
>
>    21. Your actual password is **never sent** to any external server. The tool computes the SHA-1 hash of your password, sends only the first 5 characters of that hash to the HIBP API, and compares the returned list of suffixes locally. This is called the **k-anonymity model** — meaning even HIBP cannot know what password you checked.
>
>    22. ---
>
>    23. ## Scoring System
>
>    24. The final score is determined by the number of critical and warning issues found:
>
>    25. | Score | Condition |
>    26. |---|---|
>    27. | 🔴 **VERY WEAK** | 2 or more critical issues |
>    28. | 🔴 **WEAK** | Exactly 1 critical issue |
>    29. | 🟡 **FAIR** | 2 or more warnings, no critical issues |
>    30. | 🟢 **GOOD** | Exactly 1 warning, no critical issues |
>    31. | 🟢 **STRONG** | No critical issues and no warnings |
>
>    32. If any issues are found, the tool also generates a **strong password suggestion** (18 characters, mixed case, digits and symbols) using Python's `secrets` module — because at least one of us should be responsible.
>
>    33. ---
>
>    34. ## CLI Flags Reference
>
>    35. | Flag | Description |
>    36. |---|---|
>    37. | `--no-hibp` | Skip the breach check (offline mode) |
>    38. | `--show-password` | Print the password in the report output |
>    39. | `--personal` | Prompt for name, username, birth year to check against |
>    40. | `--json` | Output results as JSON |
>    41. | `--min-score LEVEL` | Exit with code 1 if the score is below LEVEL (useful in CI pipelines) |
>    42. | `--batch FILE` | Check every password in a text file |
>
>    43. ---
>
>    44. ---
>
>    45. # 🇫🇷 Guide en Français
>
>    46. > *Parce que "motdepasse123" reste la vision de Fort Knox pour certains.*
>        >
>        > PasswordCheck est un **détecteur de vulnérabilité de mot de passe** qui analyse votre mot de passe à travers une série de vérifications de sécurité et consulte la base de données [Have I Been Pwned](https://haveibeenpwned.com/) — pour s'assurer que votre mot de passe "ultra-sécurisé" n'a pas déjà été divulgué quelques milliers de fois.
>        >
>        > ---
>        >
>        > ## 📖 Table des matières
>        >
>        > - [Fonctionnement général](#fonctionnement-général)
>        > - - [Installation](#installation-1)
>        >   - - [Utilisation — CLI](#utilisation--cli)
>        >     - - [Utilisation — Application Web](#utilisation--application-web)
>        >       - - [Vérifications de sécurité](#vérifications-de-sécurité)
>        >         - - [Système de score](#système-de-score)
>        >           - - [Référence des options CLI](#référence-des-options-cli)
>        >            
>        >             - ---
>        >
>        > ## Fonctionnement général
>        >
>        > PasswordCheck analyse un mot de passe à travers un ensemble de vérifications, calcule son entropie, estime le temps nécessaire pour le craquer, et interroge l'API HIBP pour vérifier s'il figure dans des bases de données de fuites connues. À la fin, le mot de passe reçoit un score de **VERY WEAK** à **STRONG**, et — si nécessaire — l'outil suggère un meilleur mot de passe.
>        >
>        > L'application se compose de trois couches :
>        >
>        > 1. **`password_check.py`** — Le moteur Python principal qui exécute toutes les vérifications et génère un rapport.
>        > 2. 2. **`api.py`** — Une API REST Flask légère qui expose le moteur via HTTP pour permettre à n'importe quel client de l'utiliser.
>        >    3. 3. **`frontend/`** — Une interface web React + Vite qui communique avec l'API pour vous permettre de vérifier vos mots de passe depuis un navigateur, sans toucher à un terminal.
>        >      
>        >       4. ---
>        >      
>        >       5. ## Installation
>        >      
>        >       6. ### Moteur Python et API
>
> ```bash
> # Cloner le dépôt
> git clone https://github.com/Danjummah23/PasswordCheck.git
> cd PasswordCheck
>
> # Installer les dépendances
> pip install flask flask-cors
> ```
>
> ### Frontend
>
> ```bash
> cd frontend
> npm install
> ```
>
> ---
>
> ## Utilisation — CLI
>
> ### Mode interactif *(recommandé pour les humains)*
>
> Lancez sans argument : l'outil vous demandera de saisir un mot de passe de façon sécurisée (la saisie est masquée) :
>
> ```bash
> python password_check.py
> ```
>
> ### Mode direct
>
> Passez le mot de passe directement en argument *(attention — il peut apparaître dans l'historique de votre shell, ce qui est le summum de l'ironie pour un outil de sécurité)* :
>
> ```bash
> python password_check.py "MonM0tDePasse!"
> ```
>
> ### Mode batch
>
> Vérifiez un fichier entier de mots de passe et obtenez un résumé :
>
> ```bash
> python password_check.py --batch mots_de_passe.txt
> ```
>
> ### Mode informations personnelles
>
> Fournissez votre nom, nom d'utilisateur et année de naissance pour que l'outil vérifie si votre mot de passe les contient :
>
> ```bash
> python password_check.py --personal
> ```
>
> ### Sortie JSON
>
> Obtenez une sortie lisible par une machine pour l'utiliser dans des scripts ou des pipelines :
>
> ```bash
> python password_check.py "MonM0tDePasse!" --json
> ```
>
> ---
>
> ## Utilisation — Application Web
>
> 1. Démarrez le serveur API :
> 2.  ```bash
>      python api.py
>      ```
>      L'API sera disponible à l'adresse `http://localhost:5000`.
>
> 2. Dans un autre terminal, démarrez le serveur de développement frontend :
> 3.  ```bash
>      cd frontend
>      npm run dev
>      ```
>
> 3. Ouvrez votre navigateur et rendez-vous à l'URL affichée par Vite (généralement `http://localhost:5173`).
>
> 4. 4. Saisissez un mot de passe dans le champ de saisie et obtenez vos résultats instantanément — sans terminal.
>   
>    5. Le frontend envoie une requête `POST` à `/api/check` avec votre mot de passe et affiche le rapport complet incluant le score, l'entropie, le temps de craquage et les résultats de chaque vérification.
>   
>    6. ---
>   
>    7. ## Vérifications de sécurité
>
>    8. | Vérification | Ce qu'elle détecte | Sévérité |
>    9. |---|---|---|
>    10. | **Longueur** | Moins de 8 caractères est refusé ; moins de 12 est un avertissement | Critique / Avertissement |
>    11. | **Variété de caractères** | Requiert un mélange de majuscules, minuscules, chiffres et caractères spéciaux | Critique / Avertissement |
>    12. | **Séquence clavier** | Détecte des séquences comme `qwerty`, `asdfgh`, `12345` — car taper en ligne sur le clavier n'est pas de la créativité | Critique |
>    13. | **Caractères répétés** | Signale des répétitions comme `aaa` ou `111` | Avertissement |
>    14. | **Nombres séquentiels** | Détecte des suites comme `123`, `456` | Avertissement |
>    15. | **Patterns de date** | Repère les années de naissance, formats MMJJ, JJMM, AAMMJJ — car votre date de naissance n'est pas un secret | Avertissement |
>    16. | **Leet speak** | Voit à travers `p@ssw0rd` et `l3tm31n` — l'esthétique hacker qui ne trompe personne | Critique |
>    17. | **Mots du dictionnaire** | Correspond à plus de 150 mots courants incluant prénoms, marques, culture pop et sports | Avertissement |
>    18. | **Informations personnelles** | Vérifie si votre nom, pseudo ou année de naissance apparaît dans le mot de passe | Critique |
>    19. | **Vérification HIBP** | Interroge l'API Have I Been Pwned (modèle k-anonymat — seuls les 5 premiers caractères du hash SHA-1 sont envoyés) | Critique |
>
>    20. ### Comment la vérification HIBP protège votre vie privée
>
>    21. Votre mot de passe réel n'est **jamais envoyé** à un serveur externe. L'outil calcule le hash SHA-1 de votre mot de passe, envoie uniquement les 5 premiers caractères de ce hash à l'API HIBP, et compare localement la liste des suffixes retournés. C'est le **modèle k-anonymat** — même HIBP ne peut pas savoir quel mot de passe vous avez vérifié.
>
>    22. ---
>
>    23. ## Système de score
>
>    24. Le score final est déterminé par le nombre de problèmes critiques et d'avertissements détectés :
>
>    25. | Score | Condition |
>    26. |---|---|
>    27. | 🔴 **VERY WEAK** | 2 problèmes critiques ou plus |
>    28. | 🔴 **WEAK** | Exactement 1 problème critique |
>    29. | 🟡 **FAIR** | 2 avertissements ou plus, aucun problème critique |
>    30. | 🟢 **GOOD** | Exactement 1 avertissement, aucun problème critique |
>    31. | 🟢 **STRONG** | Aucun problème critique, aucun avertissement |
>
>    32. En cas de problème détecté, l'outil génère également une **suggestion de mot de passe robuste** (18 caractères, majuscules/minuscules, chiffres et symboles) via le module Python `secrets` — parce qu'au moins l'un d'entre nous doit être responsable.
>
>    33. ---
>
>    34. ## Référence des options CLI
>
>    35. | Option | Description |
>    36. |---|---|
>    37. | `--no-hibp` | Ignorer la vérification de fuite (mode hors ligne) |
>    38. | `--show-password` | Afficher le mot de passe dans le rapport |
>    39. | `--personal` | Demander le nom, pseudo et année de naissance à vérifier |
>    40. | `--json` | Afficher les résultats en JSON |
>    41. | `--min-score NIVEAU` | Quitter avec le code 1 si le score est inférieur au NIVEAU (utile dans les pipelines CI) |
>    42. | `--batch FICHIER` | Vérifier chaque mot de passe dans un fichier texte |
>
>    43. ---
>
>    44. *Guide généré avec ❤️ — et un soupçon de honte pour chaque "password123" encore en circulation.*
>    45. 
