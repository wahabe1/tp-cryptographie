# TP 2 – Construire une infrastructure de gestion de clés

**Module :** EC2 - Ingénierie de la cryptographie
**Enseignant :** Dr Zakaria Sawadogo
**Étudiant :** CISSE Abdoul Wahabou
**Année universitaire :** 2026–2027

## Description

Mise en place avec OpenSSL d'une petite infrastructure de gestion de clés (PKI) :

| Élément | Clé et durée | Rôle |
|---|---|---|
| AC racine | P-384, 10 ans, hors ligne | Sommet de la confiance. Signe l'intermédiaire |
| AC intermédiaire | P-256, 5 ans | Signe les certificats du quotidien. Limitée à `tp.local` |
| Serveur `www.tp.local` | P-256, 90 jours | Usage « serveur TLS » |
| Client `alice@tp.local` | P-256, 90 jours | Usage « client TLS » |

On y valide les chaînes de certificats, on révoque un certificat (celui d'Alice) et on publie une liste de révocation (CRL).

## Contenu du dossier

| Fichier | Rôle |
|---|---|
| `pki.sh` | Script qui construit toute la PKI (racine, intermédiaire, serveur, client) et vérifie les chaînes |
| `racine.cnf` | Configuration de l'AC racine (extensions de l'intermédiaire : `ext_inter`) |
| `inter.cnf` | Configuration de l'AC intermédiaire (extensions `ext_serveur` et `ext_client`) |
| `certificats/racine.crt` | Certificat public de l'AC racine |
| `certificats/inter.crt` | Certificat public de l'AC intermédiaire |
| `certificats/serveur.crt` | Certificat du serveur `www.tp.local` |
| `certificats/alice.crt` | Certificat du client `alice@tp.local` (révoqué à l'étape 6) |
| `compte_rendu_tp2.pdf` | Compte rendu : observations et réponses aux questions de réflexion |

Les `.crt` sont des certificats **publics**. Aucune clé privée (`.key`) n'est déposée dans ce dépôt.

## Exécution

### Prérequis

- Une machine Linux avec **OpenSSL 3.x** (vérifier avec `openssl version`).
- Les fichiers `racine.cnf`, `inter.cnf` et `pki.sh` dans le même dossier.

### 1. Construire la PKI

Dans un **dossier vide**, par exemple :

```bash
mkdir ~/pki-essai && cd ~/pki-essai
cp /chemin/vers/TP_2/racine.cnf /chemin/vers/TP_2/inter.cnf /chemin/vers/TP_2/pki.sh .
bash pki.sh
```

Le script s'arrête à la première erreur (`set -euo pipefail`). Il refuse de s'exécuter si les dossiers `racine/` et `inter/` existent déjà, pour ne rien écraser.

Résultat attendu à la fin :

```
inter/inter.crt: OK
serveur.crt: OK
alice.crt: OK
PKI construite avec succes.
```

### 2. Valider les certificats (étape 5)

```bash
# Attendu : OK
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt

# Attendu : échec (hostname mismatch)
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname autre.example serveur.crt

# Attendu : OK
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
```

### 3. Révoquer le certificat d'Alice (étape 6)

```bash
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem

# Attendu : error 23 ... certificate revoked
openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt \
  -untrusted inter/inter.crt alice.crt

# Lire la liste de révocation
openssl crl -in inter/crl/inter.crl -noout -text
```

## Résultats obtenus

| Vérification | Résultat | Signification |
|---|---|---|
| Serveur, nom `www.tp.local` | `OK` | Chaîne valide et nom présent dans le SAN |
| Serveur, nom `autre.example` | erreur 62 : hostname mismatch | Le certificat n'est pas émis pour ce nom |
| Client Alice, usage `sslclient` | `OK` | Alice peut servir de client TLS |
| Certificat pour `www.example.com` | erreur 47 : permitted subtree violation | Nom hors de `tp.local`, refusé par celui qui valide |
| Alice après révocation | erreur 23 : certificate revoked | La CRL est prise en compte |

## Remarques

- Les clés privées et les demandes de certificat (`.key`, `.csr`) restent en local et ne sont pas versionnées.