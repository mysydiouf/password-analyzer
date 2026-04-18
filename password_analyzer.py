#!/usr/bin/env python3
"""
Password Analyzer - Analyseur de mots de passe
Sokhna Oumou Diouf

Analyse la robustesse d'un mot de passe : longueur, complexite,
motifs previsibles, entropie, temps de craquage estime.
"""

import re
import math
import hashlib

# top 50 des mots de passe les plus utilises dans le monde
# (source : rapports NordPass, Have I Been Pwned)
MDP_COURANTS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123",
    "dragon", "sunshine", "princess", "letmein", "654321",
    "monkey", "1qaz2wsx", "123321", "qwertyuiop", "superman",
    "asdfghjkl", "trustno1", "admin", "welcome", "666666",
    "hello", "charlie", "football", "shadow", "master",
    "121212", "starwars", "passw0rd", "azerty", "azertyuiop",
    "motdepasse", "soleil", "bonjour", "marseille", "doudou",
    "loulou", "jetaime", "chocolat", "coucou", "camille",
]

# motifs clavier faciles a deviner
MOTIFS_CLAVIER = [
    "qwerty", "azerty", "qwertz", "asdf", "zxcv",
    "1234", "4321", "abcd", "azer", "qsdf", "wxcv",
]

# substitutions leet speak classiques
LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
        "0": "o", "5": "s", "$": "s", "7": "t", "+": "t"}


def check_longueur(mdp):
    """Donne un score selon la longueur du mot de passe"""
    n = len(mdp)
    if n < 6:
        return 0, "Tres court, craquable en secondes"
    elif n < 8:
        return 1, "Court, en dessous du minimum recommande"
    elif n < 10:
        return 2, "Acceptable"
    elif n < 14:
        return 3, "Bonne longueur"
    elif n < 20:
        return 4, "Tres bien"
    else:
        return 5, "Excellent"


def check_complexite(mdp):
    """Verifie quels types de caracteres sont utilises"""
    criteres = {
        "minuscules": bool(re.search(r"[a-z]", mdp)),
        "MAJUSCULES": bool(re.search(r"[A-Z]", mdp)),
        "chiffres": bool(re.search(r"\d", mdp)),
        "symboles": bool(re.search(r"[^a-zA-Z0-9]", mdp)),
    }
    score = sum(criteres.values())
    return score, criteres


def check_motifs(mdp):
    """Detecte les motifs previsibles (clavier, repetitions, etc.)"""
    problemes = []
    mdp_low = mdp.lower()

    # dans la liste des mdp courants ?
    if mdp_low in MDP_COURANTS:
        problemes.append("Ce mot de passe est dans le top 50 mondial")

    # motif clavier
    for motif in MOTIFS_CLAVIER:
        if motif in mdp_low:
            problemes.append(f"Motif clavier detecte : '{motif}'")
            break

    # repetitions genre "aaa" ou "111"
    if re.search(r"(.)\1{2,}", mdp):
        problemes.append("Caracteres repetes (ex: aaa, 111)")

    # sequences numeriques 123, 456...
    for i in range(len(mdp) - 2):
        if mdp[i:i+3].isdigit():
            a, b, c = int(mdp[i]), int(mdp[i+1]), int(mdp[i+2])
            if b - a == 1 and c - b == 1:
                problemes.append("Sequence numerique (ex: 123, 456)")
                break

    # annee dans le mdp (souvent date de naissance)
    if re.search(r"(19|20)\d{2}", mdp):
        problemes.append("Contient une annee (probablement date de naissance)")

    # que des minuscules ou que des chiffres
    if mdp.isdigit():
        problemes.append("Que des chiffres, tres facile a craquer")
    elif mdp.isalpha() and mdp.islower():
        problemes.append("Que des minuscules")

    # check leet speak (p@ssw0rd -> password)
    mdp_deleet = mdp_low
    for symbole, lettre in LEET.items():
        mdp_deleet = mdp_deleet.replace(symbole, lettre)
    if mdp_deleet != mdp_low and mdp_deleet in MDP_COURANTS:
        problemes.append("Substitution leet d'un mdp courant (ex: p@ssw0rd)")

    return problemes


def calcul_entropie(mdp):
    """
    Calcule l'entropie en bits.
    Formule : E = longueur * log2(taille_alphabet)
    Plus c'est haut, plus c'est dur a craquer.
    """
    alphabet = 0
    if re.search(r"[a-z]", mdp): alphabet += 26
    if re.search(r"[A-Z]", mdp): alphabet += 26
    if re.search(r"\d", mdp): alphabet += 10
    if re.search(r"[^a-zA-Z0-9]", mdp): alphabet += 33

    if alphabet == 0:
        return 0, 0

    entropie = len(mdp) * math.log2(alphabet)
    return round(entropie, 1), alphabet


def estimer_craquage(mdp):
    """
    Estime combien de temps ca prendrait pour craquer le mdp
    en brute force avec un GPU (environ 10 milliards/seconde)
    """
    alphabet = 0
    if re.search(r"[a-z]", mdp): alphabet += 26
    if re.search(r"[A-Z]", mdp): alphabet += 26
    if re.search(r"\d", mdp): alphabet += 10
    if re.search(r"[^a-zA-Z0-9]", mdp): alphabet += 33

    if alphabet == 0:
        return "?"

    combinaisons = alphabet ** len(mdp)
    secondes = combinaisons / 10_000_000_000  # 10 milliards/s

    if secondes < 1:
        return "instantane"
    elif secondes < 60:
        return f"{secondes:.0f} secondes"
    elif secondes < 3600:
        return f"{secondes/60:.0f} minutes"
    elif secondes < 86400:
        return f"{secondes/3600:.1f} heures"
    elif secondes < 365 * 86400:
        return f"{secondes/86400:.0f} jours"
    elif secondes < 365 * 86400 * 1e6:
        return f"{secondes/(365*86400):.0f} ans"
    else:
        return "des millions d'annees"


def faire_hash(mdp):
    """Genere les hash du mdp (comme ca on voit a quoi ca ressemble)"""
    data = mdp.encode("utf-8")
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
    }


def score_global(score_long, score_complex, nb_problemes, entropie):
    """Score final sur 100"""
    score = 0
    score += score_long * 8       # max 40
    score += score_complex * 7.5  # max 30
    score += min(entropie / 4, 30)  # max 30

    # on retire des points pour chaque probleme trouve
    score -= nb_problemes * 15

    score = max(0, min(100, score))

    if score < 20:   niveau = "CRITIQUE"
    elif score < 40: niveau = "FAIBLE"
    elif score < 60: niveau = "MOYEN"
    elif score < 80: niveau = "BON"
    else:            niveau = "EXCELLENT"

    return int(score), niveau


def analyser(mdp):
    """Analyse complete d'un mot de passe"""

    # masquer le mdp dans l'affichage (securite)
    if len(mdp) > 4:
        masque = mdp[:2] + "*" * (len(mdp) - 4) + mdp[-2:]
    else:
        masque = "*" * len(mdp)

    print(f"\n  === ANALYSE ===\n")
    print(f"  Mot de passe : {masque}")
    print(f"  Longueur     : {len(mdp)} caracteres\n")

    # longueur
    s_long, comment_long = check_longueur(mdp)
    print(f"  Longueur : {comment_long}")

    # complexite
    s_comp, details = check_complexite(mdp)
    print(f"\n  Complexite :")
    for nom, ok in details.items():
        status = "OK" if ok else "manquant"
        print(f"    [{status:>8}] {nom}")

    # motifs dangereux
    problemes = check_motifs(mdp)
    if problemes:
        print(f"\n  Problemes detectes :")
        for p in problemes:
            print(f"    /!\\ {p}")
    else:
        print(f"\n  Aucun motif dangereux detecte")

    # entropie
    entropie, alphabet = calcul_entropie(mdp)
    print(f"\n  Entropie : {entropie} bits (alphabet de {alphabet} caracteres)")
    if entropie < 28:     print(f"  -> Tres faible")
    elif entropie < 36:   print(f"  -> Faible")
    elif entropie < 60:   print(f"  -> Correcte")
    elif entropie < 80:   print(f"  -> Forte")
    else:                 print(f"  -> Tres forte")

    # temps de craquage
    temps = estimer_craquage(mdp)
    print(f"\n  Temps de craquage estime (GPU) : {temps}")

    # score
    score, niveau = score_global(s_long, s_comp, len(problemes), entropie)
    barre = "#" * (score // 5) + "." * (20 - score // 5)
    print(f"\n  SCORE : {score}/100 - {niveau}")
    print(f"  [{barre}]")

    # hash
    h = faire_hash(mdp)
    print(f"\n  Hash du mot de passe :")
    print(f"    MD5    : {h['MD5']}")
    print(f"    SHA-1  : {h['SHA-1']}")
    print(f"    SHA-256: {h['SHA-256']}")
    print(f"    (les mdp sont stockes sous forme de hash, jamais en clair)")

    # conseils
    print(f"\n  === CONSEILS ===\n")
    if len(mdp) < 12:
        print(f"  - Visez au moins 12 caracteres")
    if not details["MAJUSCULES"]:
        print(f"  - Ajoutez des majuscules")
    if not details["chiffres"]:
        print(f"  - Ajoutez des chiffres")
    if not details["symboles"]:
        print(f"  - Ajoutez des symboles (!@#$%...)")
    if problemes:
        print(f"  - Evitez les motifs previsibles")
    print(f"  - Pensez aux phrases de passe : 'MonChat!Mange2Souris'")
    print(f"  - Utilisez un gestionnaire de mdp (Bitwarden, KeePass)")
    print()


def comparer(liste_mdp):
    """Compare plusieurs mots de passe entre eux"""
    print(f"\n  === COMPARAISON ===\n")

    resultats = []
    for mdp in liste_mdp:
        s_long, _ = check_longueur(mdp)
        s_comp, _ = check_complexite(mdp)
        problemes = check_motifs(mdp)
        entropie, _ = calcul_entropie(mdp)
        score, niveau = score_global(s_long, s_comp, len(problemes), entropie)

        # masquer
        if len(mdp) > 4:
            masque = mdp[:2] + "*" * (len(mdp) - 4) + mdp[-2:]
        else:
            masque = "*" * len(mdp)

        resultats.append((masque, score, niveau))

    # tri par score
    resultats.sort(key=lambda x: x[1], reverse=True)

    print(f"  {'#':<4} {'SCORE':<10} {'NIVEAU':<12} {'MOT DE PASSE'}")
    print(f"  {'--':<4} {'-----':<10} {'------':<12} {'------------'}")
    for i, (masque, score, niveau) in enumerate(resultats, 1):
        print(f"  {i:<4} {score:>5}/100  {niveau:<12} {masque}")
    print()


def main():
    print("\n  === PASSWORD ANALYZER ===\n")

    while True:
        print("  [1] Analyser un mot de passe")
        print("  [2] Comparer plusieurs mots de passe")
        print("  [3] Quitter\n")

        choix = input("  Choix : ").strip()

        if choix == "1":
            mdp = input("\n  Mot de passe : ")
            if mdp:
                analyser(mdp)
            else:
                print("  (vide)\n")

        elif choix == "2":
            print("\n  Entrez les mots de passe (un par ligne, 'fin' pour lancer)")
            liste = []
            while True:
                m = input(f"  [{len(liste)+1}] : ")
                if m.lower() == "fin":
                    break
                if m:
                    liste.append(m)
            if liste:
                comparer(liste)

        elif choix == "3":
            print("\n  Bye!\n")
            break
        else:
            print("  ?\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Interrompu.")
