import struct

import pytest
from cryptography.exceptions import InvalidTag

from coffre import chiffrer, dechiffrer, rechiffrer, TAILLE_ENTETE, T, M, P

MDP = "mot_de_passe_de_test"
NOM = "notes.txt"
DONNEES = b"Donnees confidentielles du TP de cryptographie."

# Parametres volontairement faibles : ils simulent un "vieux" fichier
ANCIENS = dict(t=1, m=8 * 1024, p=1)


def test_aller_retour():
    """Correction : on retrouve exactement les donnees d'origine."""
    blob = chiffrer(MDP, NOM, DONNEES)
    assert dechiffrer(MDP, NOM, blob) == DONNEES


def test_chiffrer_deux_fois_donne_deux_resultats_differents():
    """Chiffrement probabiliste : sel et nonce neufs a chaque appel."""
    blob1 = chiffrer(MDP, NOM, DONNEES)
    blob2 = chiffrer(MDP, NOM, DONNEES)
    assert blob1 != blob2


def test_mauvais_mot_de_passe():
    """Authentification de la cle : un mauvais mot de passe est rejete."""
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer("un_autre_mot_de_passe", NOM, blob)


def test_octet_modifie():
    """Integrite : modifier un seul octet du chiffre est detecte."""
    blob = bytearray(chiffrer(MDP, NOM, DONNEES))
    blob[TAILLE_ENTETE] ^= 0x01  # inverse un bit du premier octet chiffre
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, bytes(blob))


def test_nom_de_fichier_echange():
    """Liaison au contexte : le nom du fichier fait partie des donnees associees."""
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, "autre_fichier.txt", blob)


def test_ancien_fichier_reste_lisible():
    """Evolution : un fichier chiffre avec d'anciens parametres se dechiffre encore."""
    ancien = chiffrer(MDP, NOM, DONNEES, **ANCIENS)
    assert dechiffrer(MDP, NOM, ancien) == DONNEES


def test_rechiffrer_change_le_mot_de_passe():
    """Le nouveau mot de passe ouvre le fichier, l'ancien ne l'ouvre plus."""
    blob = chiffrer(MDP, NOM, DONNEES)
    nouveau = rechiffrer(MDP, "nouveau_mot_de_passe", NOM, blob)
    assert dechiffrer("nouveau_mot_de_passe", NOM, nouveau) == DONNEES
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, nouveau)


def test_rechiffrer_durcit_les_parametres():
    """Apres rechiffrement, l'en-tete contient les parametres actuels (T, M, P)."""
    ancien = chiffrer(MDP, NOM, DONNEES, **ANCIENS)
    assert struct.unpack(">III", ancien[4:16]) == (1, 8 * 1024, 1)
    nouveau = rechiffrer(MDP, MDP, NOM, ancien)
    assert struct.unpack(">III", nouveau[4:16]) == (T, M, P)
    assert dechiffrer(MDP, NOM, nouveau) == DONNEES


def test_rechiffrer_avec_mauvais_ancien_mot_de_passe():
    """On ne peut pas rechiffrer sans connaitre l'ancien mot de passe."""
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        rechiffrer("mauvais", "nouveau", NOM, blob)