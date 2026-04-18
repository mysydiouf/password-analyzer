# Password Analyzer

Outil en Python pour tester la robustesse d'un mot de passe. Donne un score sur 100 et explique les faiblesses.

## Ce que ça fait

- Score de robustesse sur 100 (CRITIQUE -> EXCELLENT)
- Vérifie la présence de majuscules, minuscules, chiffres, symboles
- Détecte les motifs clavier (azerty, qwerty...) et les séquences (123, abc...)
- Compare avec les 50 mots de passe les plus utilisés au monde
- Détecte les substitutions leet speak (p@ssw0rd -> password)
- Calcule l'entropie en bits (mesure mathématique de la solidité)
- Estime le temps de craquage en brute force GPU (10 milliards tentatives/sec)
- Affiche les hash MD5, SHA-1 et SHA-256 du mot de passe
- Mode comparaison pour classer plusieurs mots de passe

## Lancer le programme

```bash
python3 password_analyzer.py
```

Python 3.8+ requis, pas de dépendance externe.

## Exemple

```
  === ANALYSE ===

  Mot de passe : az*****23
  Longueur     : 9 caracteres

  Longueur : Acceptable

  Complexite :
    [      OK] minuscules
    [manquant] MAJUSCULES
    [      OK] chiffres
    [manquant] symboles

  Problemes detectes :
    /!\ Motif clavier detecte : 'azerty'
    /!\ Sequence numerique (ex: 123, 456)

  Entropie : 46.5 bits (alphabet de 36 caracteres)
  -> Correcte

  Temps de craquage estime (GPU) : 2 heures

  SCORE : 13/100 - CRITIQUE
  [##..................]
```

## Le calcul d'entropie

L'entropie mesure l'imprevisibilite du mot de passe.

Formule : `E = longueur × log2(taille_alphabet)`

Par exemple pour "azerty123" : 9 caracteres × log2(36) = 46.5 bits. C'est faible. Un bon mot de passe devrait avoir au moins 60 bits d'entropie.

## Pourquoi les hash ?

Les mots de passe ne sont jamais stockés en clair dans les bases de données (enfin normalement...). On stocke leur hash, qui est une empreinte irréversible. Le programme montre à quoi ça ressemble avec MD5, SHA-1 et SHA-256.

## Auteur

Sokhna Oumou Diouf - L2 Informatique, Sorbonne Université
