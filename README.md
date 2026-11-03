# cloudfiles

Cloud personnel de Robin, servi sur `https://cloud.robin-borg.dev` : une page d'admin
(dépôt, tri, tags, recherche, renommage, analyse IA), des liens publics `/f/` (dont les
mini-sites), des partages `/s/` à durée ou nombre d'usages limités, et un accès WebDAV sous
`/dav/` pour brancher n'importe quelle application (iji, rclone, un gestionnaire de fichiers).

Un seul binaire Go ; les fichiers vivent dans `FILES_DIR`, ce que le service sait d'eux (liens,
partages, descriptions, tags) dans la base SQLite `DB_PATH`, indexée par chemin relatif.

| Fichier | Rôle |
| --- | --- |
| `main.go` | configuration, routes, API d'admin, `/f/`, `/s/`, analyse IA |
| `auth.go`, `limits.go` | jetons d'admin, limites de débit et d'échecs, adresse du client |
| `pathdb.go` | base tenue à jour quand un chemin naît, bouge ou disparaît |
| `dav.go`, `davfs.go`, `davio.go` | WebDAV : authentification, système de fichiers, verrous, quotas |
| `serve.go` | en-têtes des fichiers servis (`Content-Disposition`, bac à sable) |

## Variables d'environnement

| Variable | Rôle |
| --- | --- |
| `ADMIN_PASSWORD` | mot de passe de la page d'admin (Bearer de l'API) ; obligatoire |
| `AUTH_TOKEN` | jeton de l'API, seul accepté par `/api/suggest` (extension Firefox) ; obligatoire |
| `BASE_URL` | adresse publique, préfixe des liens `/f/` et `/s/` |
| `FILES_DIR` | dossier des fichiers (`/data/files` par défaut) |
| `DB_PATH` | base SQLite (`/data/cloud.db` par défaut) |
| `PORT` | port d'écoute (`8080` par défaut) |
| `ANTHROPIC_API_KEY` | analyse IA des fichiers ; sans elle, `/api/analyze` et `/api/suggest` répondent 503 |
| `DAV_USER` | identifiant WebDAV |
| `DAV_PASSWORD_BCRYPT` | hash bcrypt (coût 10 au moins) du mot de passe WebDAV |
| `DAV_ROOT` | sous-dossier de `FILES_DIR` servi par WebDAV ; vide : tout |

Le service refuse de démarrer si `ADMIN_PASSWORD` ou `AUTH_TOKEN` manque ou vaut encore
`changeme-…`. Sans `DAV_USER` ni `DAV_PASSWORD_BCRYPT`, WebDAV est éteint (`/dav/` répond 404)
et le reste fonctionne. Le mot de passe WebDAV ne peut être ni vide, ni `ADMIN_PASSWORD`, ni
`AUTH_TOKEN` : le service refuse alors d'activer WebDAV.

## Générer le hash du mot de passe WebDAV

Tirer un mot de passe long et aléatoire (il ne sert qu'aux applications, 72 octets au plus),
le garder dans un gestionnaire, puis le hacher avec l'image elle-même, sans le laisser dans
l'historique du shell :

```sh
openssl rand -base64 32
read -rs P && printf '%s\n' "$P" | docker run --rm -i cloudfiles ./cloudfiles dav-hash; unset P
```

Le hash (`$2a$12$…`) va dans `DAV_PASSWORD_BCRYPT`. Il contient des `$` : dans un fichier
`.env` lu par Docker Compose ou Kamal, l'écrire entre apostrophes
(`DAV_PASSWORD_BCRYPT='$2a$12$…'`) ; le service retire ces apostrophes si l'outil les garde.

## Se brancher en WebDAV

- Adresse : `https://cloud.robin-borg.dev/dav/`
- Authentification : HTTP Basic, `DAV_USER` et le mot de passe d'application.

Exemple avec rclone : `rclone config create cloud webdav url=https://cloud.robin-borg.dev/dav/ vendor=other user=<DAV_USER> pass=$(rclone obscure '<mot de passe>')`.

Ce qui est fait par WebDAV se voit dans la page d'admin et garde la base cohérente :

- `MOVE` (renommer, déplacer) : le lien `/f/`, les partages `/s/`, la description et les tags
  suivent le fichier, et pour un dossier tout ce qu'il contient ;
- `DELETE` : liens, partages et méta du fichier (ou du dossier et de son contenu) sont effacés ;
- `PUT` : comme un dépôt par la page d'admin ; écraser un fichier garde son lien et ses
  partages ; l'analyse IA part 30 s après la dernière écriture ;
- `COPY` : la copie reprend description et tags, pas les liens ni les partages ;
- toute création (`PUT`, `COPY`, `MKCOL`, `LOCK` sur un nom neuf, dépôt ou dossier créé par
  l'admin) efface d'abord ce que la base savait encore de ce chemin : un nouveau fichier
  n'hérite jamais du lien public d'un ancien. Si la base ne répond pas, l'opération est refusée
  plutôt que de laisser un lien orphelin.

Limites : 512 Mo par fichier (comme le dépôt), 256 Mo gardés libres sur le volume (507 sinon),
`PROPFIND` limité à `Depth: 0` ou `1` (`infinity` répond 403, l'absence d'en-tête vaut `1`),
verrous `LOCK` en mémoire, une heure au plus, mille au plus, 5 identifiants faux par client et
par quart d'heure avant blocage (429), liens symboliques ni suivis ni listés. Un fichier lu par
`/dav/` dans un navigateur s'affiche dans un bac à sable (`Content-Security-Policy: sandbox`).

## Liens publics, partages et sécurité

- **Mini-sites (`/api/publish`, `/f/…`)** : une page HTML, SVG ou XML publiée garde ses
  scripts, formulaires et fenêtres, mais s'exécute dans une origine opaque
  (`Content-Security-Policy: sandbox allow-scripts …`, sans `allow-same-origin`) : elle ne peut
  lire ni la session de la page d'admin ni appeler l'API à sa place. Conséquence : un mini-site
  ne dispose plus de `localStorage` ni de cookies. Les autres types (PDF, images, vidéos)
  s'affichent comme avant.
- **Partages (`/s/…/preview`)** : une page active n'est qu'affichée, sans aucun script.
- **Partage d'un dossier** : le lien télécharge le dossier tel qu'il est au moment du
  téléchargement, en zip. Tout ce qu'on y dépose ensuite (par la page d'admin ou par WebDAV)
  devient visible par quiconque a le lien, jusqu'à son expiration ou sa suppression.
- **Limites d'essais** : 5 tentatives par client et par quart d'heure sur `/api/auth`,
  20 jetons faux sur l'API d'admin, 5 identifiants faux sur WebDAV. Le client est l'adresse
  du pair, ou, quand ce pair est sur un réseau privé (kamal-proxy), la dernière adresse de
  `X-Forwarded-For`, la seule que le proxy ajoute lui-même ; IPv6 par /64.
- **Au premier démarrage de cette version**, un ménage unique efface de la base les liens,
  partages et méta dont le fichier n'existe plus (le journal en donne le nombre). Si aucun
  chemin connu n'existe, il ne fait rien : c'est le signe d'un volume non monté.

## Développer

```sh
docker run --rm -v "$PWD:/src" -w /src golang:1.27 go test ./...
docker build -t cloudfiles .
```

Le build est en `-mod=readonly` : une dépendance s'ajoute par `go get` puis `go mod tidy`,
`go.mod` et `go.sum` committés. `routes_test.go` fige le comportement des routes d'origine,
`dav_test.go` celui de WebDAV, `attack_test.go` les scénarios de la revue de sécurité.
