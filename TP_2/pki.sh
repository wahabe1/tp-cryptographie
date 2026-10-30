#!/usr/bin/env bash
# pki.sh - Construit la PKI du TP 2 :
# AC racine, AC intermediaire, certificat serveur et certificat client.
# Prerequis : racine.cnf et inter.cnf (annexe B) dans le dossier courant.
set -euo pipefail

if [ ! -f racine.cnf ] || [ ! -f inter.cnf ]; then
  echo "Erreur : racine.cnf et inter.cnf doivent etre dans le dossier courant." >&2
  exit 1
fi
if [ -d racine ] || [ -d inter ]; then
  echo "Erreur : les dossiers racine/ et inter/ existent deja. Lancez le script dans un dossier propre." >&2
  exit 1
fi

echo "== Etape 1 : arborescence des autorites"
mkdir -p racine/certs racine/crl racine/newcerts inter/certs inter/crl inter/newcerts
touch racine/index.txt inter/index.txt
echo 1000 | tee racine/serial racine/crlnumber > /dev/null
echo 2000 | tee inter/serial inter/crlnumber > /dev/null

echo "== Etape 2 : AC racine (P-384, 10 ans)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out racine/racine.crt

echo "== Etape 3 : AC intermediaire (P-256, 5 ans)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key \
  -subj "/C=BF/O=Universite TP/CN=Inter TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

echo "== Etape 4a : certificat du serveur www.tp.local (90 jours)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
chmod 600 serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

echo "== Etape 4b : certificat du client alice@tp.local (90 jours)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
chmod 600 alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" \
  -addext "subjectAltName=email:alice@tp.local" -out alice.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt

echo "== Verification des chaines"
openssl verify -CAfile racine/racine.crt inter/inter.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt

echo "PKI construite avec succes."