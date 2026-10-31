#!/usr/bin/env bash
# tester.sh - TP 3, etapes 3 et 4 : observe la poignee de main et verifie la configuration.
# Les resultats sont aussi ecrits dans resultats_tp3.txt (a deposer avec le TP).
# Usage : bash tester.sh        (apres preparer.sh)
PKI="${PKI:-$HOME/pki-tp}"
cd "$PKI"
SORTIE="${SORTIE:-$PWD/resultats_tp3.txt}"

titre() { echo; echo "=== $* ==="; }
requete() { printf 'GET / HTTP/1.0\r\nHost: www.tp.local\r\n\r\n'; }

{
titre "1. Client valide : Bob (openssl s_client)"
requete | timeout 15 openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile racine/racine.crt \
  -cert bob.crt -key bob.key -cert_chain inter/inter.crt -brief

titre "2. Sans certificat client : le serveur doit refuser"
requete | timeout 15 openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile racine/racine.crt -brief

titre "3. Certificat revoque : Alice"
requete | timeout 15 openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile racine/racine.crt \
  -cert alice.crt -key alice.key -cert_chain inter/inter.crt -brief

titre "4. curl avec Bob"
curl --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/

titre "5. curl avec Alice (revoquee)"
curl --cacert racine/racine.crt --cert alice_chaine.crt --key alice.key https://www.tp.local/

titre "6. TLS 1.1 doit etre refuse"
echo | timeout 15 openssl s_client -connect www.tp.local:443 -tls1_1 -brief

titre "7. Suites acceptees (nmap)"
if command -v nmap > /dev/null; then
  nmap --script ssl-enum-ciphers -p 443 www.tp.local
else
  echo "nmap n'est pas installe."
fi
} 2>&1 | tee "$SORTIE"

echo
echo "Resultats enregistres dans $SORTIE"
