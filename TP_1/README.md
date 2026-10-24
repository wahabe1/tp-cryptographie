# TP 1-Chiffrement authentifié et dérivation de clés

Module : EC1-Ingénierie de la cryptographie
Enseignant : Dr Zakaria SAWADOGO
Étudiant :CISSE Abdoul wahabou
Année universitaire : 2026–2027

## Description

Mini-coffre de fichiers en Python : il chiffre un fichier avec un mot de passe.

- **Argon2id** transforme le mot de passe en clé maîtresse (avec un sel aléatoire).
- **HKDF** produit des sous-clés séparées par usage.
- **AES-GCM** chiffre les données et authentifie le contenu, l'en-tête et le nom du fichier.

### Format du fichier chiffré

| Champ | Taille | Rôle |
|---|---|---|
| Identifiant `CFR1` | 4 octets | Reconnaître le format et sa version |
| Paramètres Argon2id (t, m, p) | 12 octets | Redériver la clé et durcir plus tard |
| Sel | 16 octets | Rendre la dérivation unique pour ce fichier |
| Nonce | 12 octets | Valeur unique pour ce chiffrement |
| Chiffré + étiquette | variable | Données protégées par AES-GCM |

Les 44 premiers octets (l'en-tête) et le nom du fichier sont les données associées : ils sont authentifiés sans être chiffrés.

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `coffre.py` | Le coffre : `cle_maitresse`, `sous_cle`, `chiffrer`, `dechiffrer`, `rechiffrer` |
| `test_coffre.py` | Les 9 tests `pytest` qui vérifient les propriétés de sécurité |
| `compte_rendu_tp1.pdf` | Compte rendu : réponses aux questions de réflexion |

## Exécution

### 1. Préparation de l'environnement (une seule fois)

```bash
python3 -m venv ~/ec1
source ~/ec1/bin/activate
pip install cryptography argon2-cffi pytest
```

### 2. Lancer le coffre

```bash
python3 coffre.py
```

Le programme chiffre un message, le chiffre une seconde fois, puis le déchiffre. Il affiche la taille du fichier chiffré (message + 60 octets), l'identifiant `CFR1`, et montre que deux chiffrements du même message ne sont jamais identiques.

### 3. Lancer les tests

```bash
pytest -v
```

Résultat attendu : `9 passed`.

| Test | Propriété vérifiée |
|---|---|
| aller-retour | Correction : on retrouve les données d'origine |
| chiffrer deux fois | Chiffrement probabiliste (sel et nonce neufs) |
| mauvais mot de passe | Rejet avec `InvalidTag` |
| octet modifié | Intégrité |
| nom de fichier échangé | Liaison au contexte par les données associées |
| ancien fichier | Un fichier à anciens paramètres reste lisible |
| rechiffrer | Le nouveau mot de passe fonctionne, l'ancien est refusé |
| paramètres durcis | Après `rechiffrer`, l'en-tête contient les paramètres actuels |
| mauvais ancien mot de passe | On ne peut pas rechiffrer sans l'ancien mot de passe |

## Remarque

Aucun mot de passe réel ni aucune clé n'est enregistré dans ce dépôt.
