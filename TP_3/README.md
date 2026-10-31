# TP 3 - Déployer un canal sécurisé et gérer les certificats

Module EC1 - Ingénierie de la cryptographie (Dr Zakaria Sawadogo)
Étudiant : CISSE Abdoul Wahabou - IGIT, École Polytechnique de Ouagadougou

## Contenu du dossier

- nginx-tp3.conf : configuration du serveur TLS avec mTLS (copiée dans /etc/nginx/conf.d/tp3.conf)
- preparer.sh : émet le certificat de Bob, régénère les CRL, crée les chaînes, installe les fichiers
- tester.sh : exécute les tests de l'étape 3 et 4
- surveiller.py : supervision des dates d'expiration (codes de sortie 0, 1, 2)
- renouveler.sh : renouvellement automatique du certificat serveur avec retour arrière
- resultats_tp3.txt : sortie complète des tests
- captures/ : capture Wireshark (tp3_tls.pcapng) et 3 images commentées plus bas

Aucune clé privée n'est dans ce dépôt. Les domaines utilisés sont en *.tp.local.

## 1. Justification des directives nginx

- listen 443 ssl : le serveur écoute en HTTPS sur le port 443.
- server_name www.tp.local : le bloc ne s'applique qu'à ce nom, le même que dans le SAN du certificat.
- error_log ... info : les erreurs de certificat client ne sont écrites qu'au niveau info. Sans cette ligne, on ne verrait pas "certificate revoked" dans le journal.
- ssl_certificate : fichier qui contient le certificat serveur suivi de l'intermédiaire, jamais la racine.
- ssl_certificate_key : clé privée du serveur, installée en mode 600 (lisible seulement par root).
- ssl_protocols TLSv1.2 TLSv1.3 : on refuse TLS 1.0 et 1.1, qui sont obsolètes et vulnérables.
- ssl_ciphers : ne garde que 3 suites ECDHE-ECDSA avec AES-GCM ou ChaCha20-Poly1305. ECDHE donne la confidentialité persistante, GCM et ChaCha20 sont des chiffrements authentifiés. ECDSA correspond à nos clés P-256. Cette directive ne concerne que TLS 1.2 : en TLS 1.3, les suites sont fixées par le protocole et sont toutes sûres.
- ssl_prefer_server_ciphers off : avec des suites toutes modernes, on laisse le client choisir celle qui convient le mieux à son matériel.
- ssl_session_tickets off : sans renouvellement des clés de tickets, une clé volée permettrait de déchiffrer d'anciennes sessions (voir question 2).
- ssl_client_certificate : certificat de la racine, utilisé pour valider les certificats clients.
- ssl_verify_client on : le client DOIT présenter un certificat valide, sinon la connexion est refusée (mTLS).
- ssl_verify_depth 2 : la chaîne client peut avoir au plus 2 niveaux d'autorités (intermédiaire puis racine), ce qui correspond à notre PKI.
- ssl_crl : liste des certificats révoqués (CRL de l'intermédiaire et de la racine), pour refuser les clients comme Alice.
- add_header Strict-Transport-Security "max-age=31536000" always : impose HTTPS au navigateur pendant un an. "always" ajoute l'en-tête même pour les réponses d'erreur.
- location / avec return 200 : réponse simple "Bonjour" suivie du DN du client, ce qui prouve que l'authentification a réussi.

## 2. Résultats des tests

| Test | Résultat attendu | Résultat obtenu |
|---|---|---|
| Version TLS | TLS 1.3 | TLSv1.3 |
| Suite de chiffrement | AEAD | TLS_AES_256_GCM_SHA384 |
| Groupe d'échange de clés | courbe moderne | X25519 |
| Client Bob (certificat valide) | accepté | Bonjour CN=bob@tp.local |
| Sans certificat client | refusé | 400 No required SSL certificate was sent |
| Client Alice (révoquée) | refusé | 400 The SSL certificate error, journal : 23:certificate revoked |
| TLS 1.1 | refusé | échec de la poignée de main (alert 70, protocol version) |
| nmap, TLS 1.2 | suites ECDHE seulement | 3 suites ECDHE-ECDSA, toutes notées A |
| nmap, TLS 1.3 | suites AEAD | 3 suites, toutes notées A |
| surveiller.py, certificat de 5 jours | CRITIQUE, code 2 | CRITIQUE, code 2 |
| surveiller.py, certificats sains | OK, code 0 | OK, code 0 |
| renouveler.sh --force | série 2000 vers 2005, serveur actif | réussi, sauvegarde dans pki-tp/sauvegardes |

Alice est refusée parce que son certificat figure dans la CRL de l'intermédiaire (raison keyCompromise, déclarée au TP 2). nginx vérifie la CRL sur toute la chaîne grâce à crls.pem et ssl_crl.

La sortie complète est dans resultats_tp3.txt.

## 3. Analyse Wireshark (captures/)

La capture a été faite sur l'interface lo avec deux connexions curl, l'une en TLS 1.3 et l'autre en TLS 1.2 seulement.

- 01_hello_tls13.png : après la poignée de main TCP (SYN, SYN-ACK, ACK), le Client Hello puis le Server Hello en TLSv1.3. Le Server Hello est suivi de Change Cipher Spec et de données qui apparaissent seulement comme Application Data.
- 02_certificat_tls12.png : avec le filtre tls.handshake.type == 11, seules 2 lignes apparaissent, toutes deux en TLSv1.2. Le paquet 23 (serveur vers client) contient Server Hello, Certificate, Server Key Exchange et Certificate Request. Le paquet 25 (client vers serveur) contient le Certificate de Bob. Les certificats sont lisibles en clair.
- 03_tls13_chiffre.png : en TLS 1.3, aucun message Certificate n'est visible.

Explication : en TLS 1.3, l'échange de clés (X25519) a lieu dès le Client Hello et le Server Hello. Les deux côtés peuvent donc dériver des clés avant la suite de la poignée de main, et tous les messages suivants sont chiffrés (EncryptedExtensions, Certificate, CertificateVerify, Finished). Un observateur ne voit ni le certificat du serveur, ni celui du client. En TLS 1.2, les certificats sont envoyés avant que la clé de session existe, donc ils sont visibles.

## 4. Questions de réflexion

1. Pourquoi le serveur ne doit-il pas envoyer la racine ? Le client doit déjà posséder la racine dans son magasin de confiance : c'est l'ancre de confiance. Une racine envoyée par le serveur ne prouve rien, car un attaquant pourrait en envoyer une fausse. L'envoyer ne fait que gaspiller des octets.

2. Pourquoi désactiver les tickets de session ? Les tickets sont chiffrés avec une clé du serveur. Si cette clé n'est pas renouvelée, quiconque la vole peut déchiffrer toutes les sessions passées qui ont utilisé des tickets, ce qui annule la confidentialité persistante apportée par ECDHE.

3. Que garantit HSTS ? Après une première visite, le navigateur refuse HTTP pendant la durée max-age (un an ici) et passe toujours en HTTPS. Il protège contre le SSL stripping, où un attaquant qui contrôle le réseau force le client à rester en HTTP. La toute première visite reste vulnérable, sauf avec la liste de préchargement des navigateurs.

4. Certificats de 100 jours en 2027, puis 47 jours en 2029. Un renouvellement manuel devient impossible : avec 47 jours, il faut renouveler environ 8 fois par an et par certificat, et une seule oubli provoque une panne de service. Il faut automatiser, par exemple avec un protocole comme ACME, avec supervision (surveiller.py) et retour arrière (renouveler.sh).

5. Chaîne incomplète. Certains clients (navigateurs, Windows) gardent en cache des intermédiaires déjà vus ou les téléchargent grâce à l'extension AIA du certificat. D'autres (curl, OpenSSL, Java) ne le font pas et refusent la connexion. Le serveur doit donc toujours envoyer la chaîne complète sauf la racine.

6. Procédure si la clé privée du serveur fuit.
   - Générer tout de suite une nouvelle clé et une nouvelle demande de certificat.
   - Faire émettre un nouveau certificat par l'intermédiaire.
   - Révoquer l'ancien certificat (raison keyCompromise) et republier la CRL.
   - Vérifier la chaîne, déployer, tester nginx puis recharger.
   - Renouveler les clés de tickets de session si elles existaient.
   - Chercher la cause de la fuite (accès, droits des fichiers, journaux) et corriger.
   - Grâce à ECDHE, le trafic passé enregistré ne peut pas être déchiffré avec la clé volée.
