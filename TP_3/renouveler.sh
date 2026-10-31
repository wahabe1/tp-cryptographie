#!/usr/bin/env bash
# renouveler.sh - TP 3, etape 6 : renouvelle le certificat du serveur www.tp.local
# s'il expire dans moins de 30 jours.
#   1. genere une nouvelle cle et une nouvelle demande de certificat
#   2. la fait signer par l'intermediaire
#   3. verifie la chaine AVANT tout deploiement
#   4. installe les fichiers, teste la configuration, recharge nginx sans interruption
#   5. garde l'ancien certificat pour un retour en arriere
#
# Usage : ./renouveler.sh [--force]      (--force : renouveler meme si le certificat est recent)
# Pour cron (root) : PKI=/home/kali/pki-tp /home/kali/pki-tp/renouveler.sh
set -euo pipefail

PKI="${PKI:-$HOME/pki-tp}"        # dossier de la PKI du TP 2
TLS="${TLS:-/etc/nginx/tls}"      # dossier lu par nginx
SEUIL_JOURS=30
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

journal() { echo "[$(date '+%F %T')] $*"; }

cd "$PKI"

# Si le script tourne en root (cron), on rend les fichiers a leur proprietaire a la fin.
PROPRIO="$(stat -c '%u:%g' "$PKI")"
trap '$SUDO chown -R "$PROPRIO" "$PKI" 2>/dev/null || true' EXIT

ACTUEL="$TLS/serveur_chaine.crt"

# --- Faut-il renouveler ? ---
if [ "$FORCE" -eq 0 ] && openssl x509 -in "$ACTUEL" -noout -checkend $((SEUIL_JOURS * 86400)) > /dev/null; then
  journal "Le certificat est valable plus de $SEUIL_JOURS jours : rien a faire."
  exit 0
fi

journal "Renouvellement du certificat du serveur."
NOUVEAU="$(mktemp -d "$PKI/renouvellement.XXXXXX")"

# --- 1. Nouvelle cle et nouvelle demande ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$NOUVEAU/serveur.key"
chmod 600 "$NOUVEAU/serveur.key"
openssl req -new -key "$NOUVEAU/serveur.key" -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$NOUVEAU/serveur.csr"

# --- 2. Signature par l'intermediaire ---
# La base refuse par defaut deux certificats avec le meme sujet : on l'autorise.
echo "unique_subject = no" > inter/index.txt.attr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$NOUVEAU/serveur.csr" -out "$NOUVEAU/serveur.crt"

# --- 3. Verification avant deploiement (le script s'arrete si l'un des tests echoue) ---
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local "$NOUVEAU/serveur.crt" > /dev/null
EMPREINTE_CERT="$(openssl x509 -in "$NOUVEAU/serveur.crt" -noout -pubkey | openssl sha256)"
EMPREINTE_CLE="$(openssl pkey -in "$NOUVEAU/serveur.key" -pubout | openssl sha256)"
if [ "$EMPREINTE_CERT" != "$EMPREINTE_CLE" ]; then
  journal "ERREUR : le certificat ne correspond pas a la cle. Abandon."
  exit 1
fi
journal "Chaine verifiee : OK."

# --- 4. Sauvegarde de l'ancien, puis installation ---
SAUVEGARDE="$PKI/sauvegardes/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SAUVEGARDE"
$SUDO cp "$TLS/serveur.key" "$ACTUEL" "$SAUVEGARDE/"
$SUDO chown -R "$PROPRIO" "$SAUVEGARDE"

cat "$NOUVEAU/serveur.crt" inter/inter.crt > "$NOUVEAU/serveur_chaine.crt"
$SUDO install -m 600 "$NOUVEAU/serveur.key" "$TLS/serveur.key"
$SUDO install -m 644 "$NOUVEAU/serveur_chaine.crt" "$ACTUEL"

if $SUDO nginx -t && $SUDO systemctl reload nginx; then
  journal "Nouveau certificat deploye (rechargement sans interruption)."
else
  journal "ERREUR : retour a l'ancien certificat."
  $SUDO install -m 600 "$SAUVEGARDE/serveur.key" "$TLS/serveur.key"
  $SUDO install -m 644 "$SAUVEGARDE/serveur_chaine.crt" "$ACTUEL"
  $SUDO nginx -t && $SUDO systemctl reload nginx
  exit 1
fi

# --- 5. Garder une copie du nouveau certificat dans la PKI ---
cp "$NOUVEAU/serveur.key" serveur.key
cp "$NOUVEAU/serveur.crt" serveur.crt
rm -rf "$NOUVEAU"
journal "Termine. Ancien certificat conserve dans $SAUVEGARDE"
openssl x509 -in serveur.crt -noout -serial -enddate
