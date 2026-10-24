import os
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

T, M, P = 3, 256 * 1024, 4  # temps, memoire (Kio), parallelisme

IDENTIFIANT = b"CFR1"
TAILLE_SEL = 16
TAILLE_NONCE = 12
TAILLE_ENTETE = 4 + 12 + TAILLE_SEL + TAILLE_NONCE  # 44 octets
TAILLE_ETIQUETTE = 16


def cle_maitresse(mot_de_passe: str, sel: bytes, t=T, m=M, p=P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes, t=T, m=M, p=P) -> bytes:
    """Chiffre `donnees` et rend : en-tete + chiffre + etiquette."""
    sel = os.urandom(TAILLE_SEL)
    nonce = os.urandom(TAILLE_NONCE)
    entete = IDENTIFIANT + struct.pack(">III", t, m, p) + sel + nonce

    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    donnees_associees = entete + nom.encode("utf-8")
    chiffre = AESGCM(cle).encrypt(nonce, donnees, donnees_associees)
    return entete + chiffre


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Rend les donnees d'origine, ou leve une exception si quoi que ce soit ne va pas."""
    if len(blob) < TAILLE_ENTETE + TAILLE_ETIQUETTE or blob[:4] != IDENTIFIANT:
        raise ValueError("Format de fichier inconnu")

    entete = blob[:TAILLE_ENTETE]
    t, m, p = struct.unpack(">III", entete[4:16])
    sel = entete[16:16 + TAILLE_SEL]
    nonce = entete[16 + TAILLE_SEL:TAILLE_ENTETE]

    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    donnees_associees = entete + nom.encode("utf-8")
    return AESGCM(cle).decrypt(nonce, blob[TAILLE_ENTETE:], donnees_associees)


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe d'un fichier et le rechiffre avec les parametres actuels."""
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)


if __name__ == "__main__":
    message = b"Bonjour, ceci est un message secret."
    blob1 = chiffrer("mon_mot_de_passe", "notes.txt", message)
    blob2 = chiffrer("mon_mot_de_passe", "notes.txt", message)

    print("Taille du message :", len(message), "octets")
    print("Taille du fichier chiffre :", len(blob1), "octets")
    print("Debut du fichier :", blob1[:4])
    print("Deux chiffrements identiques ?", blob1 == blob2)
    print("Dechiffre :", dechiffrer("mon_mot_de_passe", "notes.txt", blob1))
