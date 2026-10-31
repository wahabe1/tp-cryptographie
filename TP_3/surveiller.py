#!/usr/bin/env python3
"""surveiller.py - TP 3, etape 5 : supervision des dates d'expiration.

Lit tous les certificats d'un dossier et affiche, pour chacun, le nombre de
jours restants avec trois niveaux :
    OK        : 30 jours ou plus
    ALERTE    : moins de 30 jours
    CRITIQUE  : moins de 7 jours (ou deja expire)

Le code de sortie vaut 0, 1 ou 2 (le pire niveau rencontre), pour pouvoir
etre utilise par un outil de supervision.

Usage : python3 surveiller.py [dossier]
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

OK, ALERTE, CRITIQUE = 0, 1, 2
NOMS = {OK: "OK", ALERTE: "ALERTE", CRITIQUE: "CRITIQUE"}
EXTENSIONS = {".crt", ".pem", ".cer"}


def date_fin(cert):
    """Date de fin de validite, avec fuseau horaire UTC."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # anciennes versions de la bibliotheque
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def niveau(jours, seuil_alerte, seuil_critique):
    """Niveau d'alerte pour un nombre de jours restants."""
    if jours < seuil_critique:
        return CRITIQUE
    if jours < seuil_alerte:
        return ALERTE
    return OK


def lire_certificats(fichier):
    """Rend la liste des certificats d'un fichier PEM (vide si ce n'est pas un certificat)."""
    try:
        return x509.load_pem_x509_certificates(fichier.read_bytes())
    except ValueError:
        return []


def main():
    analyse = argparse.ArgumentParser(description="Supervision des expirations de certificats")
    analyse.add_argument("dossier", nargs="?", default=".", help="dossier contenant les certificats")
    analyse.add_argument("--alerte", type=int, default=30, help="seuil ALERTE en jours (defaut 30)")
    analyse.add_argument("--critique", type=int, default=7, help="seuil CRITIQUE en jours (defaut 7)")
    args = analyse.parse_args()

    dossier = Path(args.dossier)
    if not dossier.is_dir():
        print(f"Erreur : {dossier} n'est pas un dossier.", file=sys.stderr)
        return CRITIQUE

    maintenant = datetime.now(timezone.utc)
    pire = OK
    trouves = 0

    fichiers = sorted(
        f for f in dossier.rglob("*") if f.is_file() and f.suffix.lower() in EXTENSIONS
    )
    for fichier in fichiers:
        for cert in lire_certificats(fichier):
            trouves += 1
            # Jours restants (le niveau est calcule sur la valeur exacte,
            # l'affichage est arrondi a l'entier le plus proche).
            jours_exacts = (date_fin(cert) - maintenant).total_seconds() / 86400
            jours = round(jours_exacts)
            niv = niveau(jours_exacts, args.alerte, args.critique)
            pire = max(pire, niv)
            etat = f"{jours} jours" if jours_exacts >= 0 else f"expire depuis {-jours} jours"
            sujet = cert.subject.rfc4514_string()
            print(f"{NOMS[niv]:<9} {etat:<22} {fichier.name}  ({sujet})")

    if trouves == 0:
        print(f"Aucun certificat trouve dans {dossier}.")
        return ALERTE

    print(f"Resultat global : {NOMS[pire]} (code de sortie {pire})")
    return pire


if __name__ == "__main__":
    sys.exit(main())
