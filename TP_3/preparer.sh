#!/usr/bin/env bash
# preparer.sh - TP 3, etape 1 : prepare les fichiers et configure nginx.
#  - emet le certificat client de Bob (Alice a ete revoquee au TP 2)
#  - regenere les listes de revocation (CRL)
#  - construit les chaines et les installe dans /etc/nginx/tls
#  - installe la configuration nginx et la recharge
# Usage : bash preparer.sh        (PKI=/autre/dossier pour changer le dossier de la PKI)
set -euo pipefail

PKI="${PKI:-$HOME/pki-tp}"
TLS=/etc/nginx/tls
ICI="$(cd "$(dirname "$0")" && pwd)"

cd "$PKI"

if [ ! -f serveur.crt ] || [ ! -f inter/inter.crt ] || [ ! -f racine/racine.crt ]; then
  echo "Erreur : la PKI du TP 2 est introuvable dans $PKI." >&2
  exit 1
fi

echo "== 1. Certificat client de Bob"
if [ -f bob.crt ]; then
  echo "bob.crt existe deja : on ne le refait pas."
else
  # inter.cnf (annexe B) ecrit le SAN alice@tp.local dans ext_client :
  # pour Bob, on retire cette ligne afin que l'adresse vienne de sa demande.
  sed '/^subjectAltName *= *email:alice@tp.local/d' inter.cnf > inter_bob.cnf
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bob.key
  chmod 600 bob.key
  openssl req -new -key bob.key -subj "/CN=bob@tp.local" \
    -addext "subjectAltName=email:bob@tp.local" -out bob.csr
  openssl ca -batch -notext -config inter_bob.cnf -extensions ext_client -days 90 \
    -in bob.csr -out bob.crt
fi
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt -purpose sslclient bob.crt

echo "== 2. Listes de revocation (valables 7 jours : relancer ce script pour les rafraichir)"
openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem

echo "== 3. Chaines de certificats"
cat serveur.crt inter/inter.crt > serveur_chaine.crt   # serveur + intermediaire, jamais la racine
cat bob.crt inter/inter.crt > bob_chaine.crt           # le client presente aussi son intermediaire
cat alice.crt inter/inter.crt > alice_chaine.crt

echo "== 4. Installation dans $TLS"
sudo mkdir -p "$TLS"
sudo install -m 600 serveur.key "$TLS/serveur.key"
sudo install -m 644 serveur_chaine.crt racine/racine.crt crls.pem "$TLS/"

echo "== 5. Nom de domaine de laboratoire"
grep -q "www.tp.local" /etc/hosts || echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts

echo "== 6. Configuration nginx"
sudo cp "$ICI/nginx-tp3.conf" /etc/nginx/conf.d/tp3.conf
sudo nginx -t
sudo systemctl enable nginx > /dev/null 2>&1 || true
sudo systemctl restart nginx
echo "Serveur pret : https://www.tp.local/"
