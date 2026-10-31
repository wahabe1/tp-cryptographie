# tp-cryptographie
# Module EC1 - Ingénierie de la cryptographie

Travaux pratiques de cryptographie, année universitaire 2026-2027.

- Étudiant : CISSE Abdoul Wahabou, 2e année de génie informatique (IGIT)
- École : École Polytechnique de Ouagadougou (EPO)
- Enseignant : Dr Zakaria Sawadogo

## Organisation du dépôt

| Dossier | Thème | Contenu principal |
|---|---|---|
| TP_1 | Chiffrement authentifié et dérivation de clés | coffre.py, test_coffre.py, compte_rendu_tp1.pdf, README.md |
| TP_2 | Infrastructure de gestion de clés (PKI) avec OpenSSL | racine.cnf, inter.cnf, pki.sh, certificats/, compte_rendu_tp2.pdf, README.md |
| TP_3 | Canal TLS sécurisé, mTLS et gestion des certificats | nginx-tp3.conf, preparer.sh, tester.sh, surveiller.py, renouveler.sh, resultats_tp3.txt, captures/, README.md |

Chaque dossier contient son propre README qui explique les choix techniques.
Pour les TP 1 et 2, les réponses aux questions se trouvent dans le compte rendu PDF.
Pour le TP 3, il n'y a pas de rapport séparé : les réponses aux questions et l'analyse des captures sont dans le README du dossier TP_3.

## Résumé des travaux

**TP 1 - Mini-coffre de fichiers.** Module Python qui chiffre un fichier avec un mot de passe : dérivation de clé avec Argon2id, sous-clés avec HKDF, chiffrement AES-GCM, format de fichier versionné dont l'en-tête et le nom du fichier sont authentifiés. Des tests pytest prouvent la correction, le chiffrement probabiliste, le rejet d'un mauvais mot de passe, la détection d'une modification et la liaison au nom du fichier.

**TP 2 - PKI.** Autorité racine (P-384, 10 ans) et autorité intermédiaire (P-256, 5 ans, pathlen:0, contraintes de nom limitées à tp.local). Émission de certificats serveur (www.tp.local) et client, validation de chaîne, refus par les contraintes de nom, révocation d'un certificat client et publication des CRL. Le script pki.sh automatise la construction.

**TP 3 - TLS et mTLS.** Serveur nginx en TLS 1.2 et 1.3 avec suites ECDHE modernes, authentification mutuelle des clients par certificat et vérification des CRL. Tests : client valide accepté, client sans certificat refusé, client révoqué refusé, TLS 1.1 refusé, analyse nmap des suites. Supervision des expirations (surveiller.py, codes de sortie 0, 1, 2), renouvellement automatique avec retour arrière (renouveler.sh, planifié avec cron) et capture Wireshark montrant que le certificat est visible en TLS 1.2 mais chiffré en TLS 1.3.

## Environnement

- Machine virtuelle Kali Linux (VirtualBox) sur hôte Windows
- OpenSSL 3.0.9, nginx 1.24.0, nmap, Wireshark
- Python 3 avec un environnement virtuel (cryptography, argon2-cffi, pytest)

## Règles de sécurité respectées

- Aucune clé privée (.key) ni mot de passe dans le dépôt, le fichier .gitignore bloque ces fichiers.
- Seuls les certificats publics sont fournis.
- Tous les tests ont été faits sur des domaines de laboratoire (*.tp.local) et sur ma propre machine.
- Aucun algorithme cryptographique n'a été réinventé : les primitives viennent de bibliothèques standard.

