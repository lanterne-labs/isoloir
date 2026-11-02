# Comment fonctionne un vote isoloir (version technique)

Ce document explique, pour un lecteur curieux de technique, ce qui se
passe à chaque étape d’un vote isoloir : l’inscription avec un
passeport, le bulletin, le comptage et la vérification. La référence
reste la spécification ([SPEC.md](../SPEC.md)) ; les mécanismes, les
limites et les évolutions prévues sont dans [DESIGN.md](../DESIGN.md).

Les rôles :

| Rôle | Ce qu’il détient | Ce qu’il fait |
|---|---|---|
| Votre navigateur | votre secret `s` | s’inscrit, vote, vérifie |
| L’app ZKPassport | la lecture de la puce | calcule la preuve d’éligibilité, sur le téléphone |
| Les relais | rien | transportent les messages (relais Nostr publics, tenus par d’autres) |
| Le serveur d’inscription (« ingest ») | la clé du registre | vérifie, inscrit, accuse réception, signe les points de contrôle |
| L’autorité | la clé de l’élection | déchiffre les sommes, jamais un bulletin publié seul |
| Le miroir | rien | sert le registre en fichiers statiques |
| N’importe qui | rien | recompte tout à partir du registre |

## 1. S’inscrire : un passeport, une clé

- Votre navigateur crée votre secret `s`, à partir d’une clé d’accès
  (Face ID, empreinte : la sortie PRF de la clé d’accès) ou de 12 mots.
  `s` ne quitte jamais vos appareils ; seule son empreinte publique,
  une feuille de l’arbre des votants, est publiée.
- L’app ZKPassport lit la puce du passeport (NFC) et calcule sur le
  téléphone une preuve à divulgation nulle de connaissance : passeport
  authentique (signé par l’État émetteur), titulaire majeur et de la
  nationalité demandée, document valide. La preuve est liée à
  l’inscription et ne révèle ni nom, ni photo, ni numéro : seulement un
  identifiant propre au passeport et au site (`uid`).
- L’inscription part sur un relais public. Le serveur la lit, vérifie la
  preuve avec le vérificateur ouvert du SDK ZKPassport (les racines du
  registre des certificats sont lues sur Ethereum), refuse un `uid` déjà
  inscrit, puis l’inscrit dans le registre public, preuve comprise.
- Chacun peut donc vérifier que chaque votant vient d’un vrai passeport,
  et qu’aucun passeport n’a deux inscriptions. L’`uid` étant public,
  l’État qui a signé la puce pourrait savoir qu’un passeport s’est
  inscrit ; jamais pour qui il vote.

## 2. Voter : un bulletin chiffré, sans nom

- Votre navigateur chiffre le bulletin (ElGamal exponentiel sur la
  courbe Grumpkin) avec la clé publique de l’élection, puis calcule une
  preuve (Noir, UltraHonk ; le setup universel d’Aztec, aucune
  cérémonie à nous) : le bulletin vient d’une feuille de l’arbre des
  votants, sans dire laquelle ; il respecte les règles du scrutin ; il
  est bien chiffré.
- Le bulletin porte un pseudonyme `H(poll, s)`, le même pour tous vos
  bulletins de ce scrutin et sans lien avec votre inscription : un
  nouveau bulletin remplace l’ancien, seul le dernier compte.
- Il est signé par une clé jetable et part sur un relais public, choisi
  par un hachage de `s`. Il ne passe jamais par le serveur de
  l’organisateur : le serveur le lit sur les relais, parmi les autres,
  et ne voit donc pas votre adresse IP. Le relais la voit, comme tout
  site visité, avec un bulletin chiffré qu’il ne peut pas lire.
- Le serveur accuse réception par un message signé qui nomme le point de
  contrôle à venir. Votre navigateur retrouve ensuite le bulletin dans le
  registre, intact ; s’il manque, l’accusé signé devient une plainte que
  chacun peut juger.

## 3. Compter sans lire

- Les bulletins chiffrés s’additionnent sans être ouverts. L’autorité
  déchiffre la somme des derniers bulletins de chaque pseudonyme et joint
  des preuves de Chaum-Pedersen : chacun vérifie le déchiffrement sans la
  clé.
- Pour un scrutin ouvert, un résultat est publié après `k_real`
  bulletins modifiés et `min_gap` secondes, en dehors des périodes de
  silence. Avec `k_real` = 1, chaque mise à jour révèle la différence
  avec la précédente, c’est-à-dire un bulletin, sans lien avec son
  auteur. Ces réglages ne peuvent qu’augmenter.
- Le vote blanc est un bulletin à part entière : il compte parmi les
  votants. Retirer son vote est un bulletin comme un autre : dans le
  registre, rien ne le distingue.

## 4. Vérifier, sans faire confiance

- Tout entre dans un registre public : un arbre de Merkle (RFC 6962).
  Le serveur en signe l’état à intervalles réguliers (des « notes
  signées » Ed25519, format C2SP), et chaque point de contrôle est
  horodaté dans Bitcoin par OpenTimestamps : impossible ensuite de faire
  passer un autre registre pour celui de cette date.
- Les refus aussi sont inscrits, avec le message refusé : un auditeur
  juge chaque message que le serveur a jugé. Les relais gardent des
  copies : un message reçu et jamais jugé se verrait.
- L’audit rejoue tout : chaque signature, chaque preuve de passeport,
  chaque preuve de bulletin, chaque refus, chaque somme et chaque
  déchiffrement. Il tourne en ligne de commande (`isoloir audit`) ou
  dans un navigateur (`audit()` de `@isoloir/web`), avec le même code.
  Une vérification qui n’a pas pu se faire est une anomalie, jamais un
  succès.

## 5. Ce que l’organisateur reçoit, ce qui reste chez vous

Reçu : « majeur, nationalité, document valide : oui », l’`uid` du
passeport pour ce site, l’empreinte publique de votre clé, des bulletins
chiffrés lus sur les relais, et les sommes déchiffrées.

Reste chez vous : votre nom, votre photo, votre date de naissance, le
numéro du passeport ; votre secret et vos 12 mots ; quel bulletin est le
vôtre ; votre adresse IP, qui ne va qu’aux relais et au miroir.

## 6. Les limites

- Une seule autorité détient la clé de l’élection : elle pourrait
  déchiffrer un bulletin seul, sans savoir de qui il vient. Le
  déchiffrement à plusieurs (seuil) est prévu, pas encore construit.
- Un votant peut prouver son vote à un tiers en révélant son secret :
  l’achat de votes n’est pas empêché.
- Un registre en deux versions (une « fourche ») se détecte, il n’est
  pas empêché ; voir DESIGN §2 et §3.
- Il faut un smartphone NFC et un passeport à puce. Qui aurait une
  copie complète de la puce pourrait inscrire le passeport avant son
  titulaire.
- ZKPassport est open source et audité en interne, pas encore par un
  tiers.

## Pour aller plus loin

- [SPEC.md](../SPEC.md) : le protocole complet.
- [DESIGN.md](../DESIGN.md) : mécanismes, limites, évolutions.
- [OPERATING.md](../OPERATING.md) : faire tourner un registre, l’auditer.
- ZKPassport : <https://github.com/zkpassport> · Noir :
  <https://noir-lang.org> · OpenTimestamps : <https://opentimestamps.org>
