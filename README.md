# cloudfiles

Cloud personnel de Robin, servi sur `https://cloud.robin-borg.dev` : une page d'admin
(dépôt, tri, tags, recherche, renommage, analyse IA), des liens publics `/f/` (dont les
mini-sites), des partages `/s/` à durée ou nombre d'usages limités, un accès WebDAV sous
`/dav/` pour brancher n'importe quelle application (iji, rclone, un gestionnaire de fichiers), et
sous `/api/dav/` une petite API de liens ouverte par les mêmes identifiants.

Un seul binaire Go ; les fichiers vivent dans `FILES_DIR`, ce que le service sait d'eux (liens,
partages, descriptions, tags) dans la base SQLite `DB_PATH`, indexée par chemin relatif.

| Fichier | Rôle |
| --- | --- |
| `main.go` | configuration, routes, API d'admin, `/f/`, `/s/`, analyse IA |
| `auth.go`, `limits.go` | jetons d'admin, limites de débit et d'échecs, adresse du client |
| `pathdb.go` | base tenue à jour quand un chemin naît, bouge ou disparaît |
| `dav.go`, `davfs.go`, `davio.go` | WebDAV : authentification, système de fichiers, verrous, quotas |
| `davlinks.go` | l'API de liens de WebDAV (`/api/dav/`) |
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

## L'API de liens de WebDAV

Sous `/api/dav/`, les identifiants WebDAV (HTTP Basic, `DAV_USER` et le mot de passe
d'application) ouvrent une petite API pour l'application branchée en WebDAV (iji) : des liens de
téléchargement vers les fichiers du dossier que sert WebDAV (`DAV_ROOT`), et de lui seul. Ni
`ADMIN_PASSWORD` ni `AUTH_TOKEN` ne l'ouvrent ; WebDAV éteint, elle répond 404. Elle ne demande
aucune variable de plus.

| Requête | Réponse |
| --- | --- |
| `POST /api/dav/links`, `{"path": "/Perso/Plan.pdf", "expires_in": "30d", "max_uses": null}` | 201, le lien |
| `GET /api/dav/links?path=/Perso/Plan.pdf` | `{"links": […]}` : ceux que l'API a faits pour ce fichier, actifs ou non |
| `GET /api/dav/links/{slug}` | le lien, où que soit son fichier dans le dossier |
| `DELETE /api/dav/links/{slug}` | `{"success": true}` |
| `GET /api/dav/shared-folders` | `{"folders": ["/Projets"]}` |

- `path` est le nom WebDAV du fichier (ce qui suit `/dav/`), résolu comme WebDAV le fait : rien
  hors du dossier, aucun lien symbolique, aucun envoi en cours. Un dossier se refuse (400) ; un
  fichier absent, hors du dossier ou derrière un lien répond 404, sans dire lequel. Un nom que la
  page de partage lirait comme un autre (une espace, même insécable, au bord d'un nom : `safePath`
  les retire) répond 404 aussi, et la page refuse un partage dont le fichier a pris un tel nom :
  elle servirait un autre fichier, ou ce qu'un lien symbolique du même nom désigne.
- Un lien est un partage `/s/` ordinaire, visible dans la page d'admin : son adresse
  (`BASE_URL/s/` et 16 caractères tirés au hasard) ne se choisit pas. `expires_in` vaut `1d`,
  `7d`, `30d` ou `never` ; `max_uses` va de 1 à 1 000, ou `null` sans borne ; visites et
  téléchargements se comptent comme pour tout partage. Chaque lien : `slug`, `url`, `path`,
  `expires_at` (`null` sans limite), `max_uses`, `uses_count`, `views_count`, `status`
  (`active`, `expired`, `exhausted`), `created_at`.
- L'API ne liste et ne révoque que les liens qu'elle a faits (colonne `created_by` de `shares`,
  `dav`, qui ne change pas avec `DAV_USER`), dans le dossier de WebDAV. Un slug qu'aucun partage
  n'a répond 404 ; un partage vivant qu'elle ne gère pas (fait depuis la page d'admin, ou dont le
  fichier est sorti du dossier de WebDAV) répond 409 : le client ne doit pas le croire parti. Un
  lien suit son fichier quand WebDAV le renomme ou le déplace, et part avec lui.
- Un lien de l'API borné en téléchargements n'a pas d'aperçu (`/preview` renvoie à la page, qui ne
  montre pas l'image) : l'aperçu sert le fichier entier sans compter de téléchargement. Pour tout
  partage, un téléchargement se réserve en une requête : des téléchargements en parallèle ne
  dépassent pas la borne.
- `shared-folders` dit quels dossiers du dossier WebDAV un partage actif rend publics, quel qu'en
  soit l'auteur, et `/` quand c'est le dossier de WebDAV lui-même ou un dossier au-dessus :
  l'application n'y range rien, puisque tout ce qu'on y dépose devient public.
- Bornes : un corps JSON (`Content-Type: application/json`) de 4 Kio au plus, sans champ inconnu ;
  1 000 liens vivants au plus (422 au-delà, les liens expirés ne comptent pas) ; 60 créations et
  révocations par client et par minute ; les identifiants faux comptent avec ceux de WebDAV (5 par
  quart d'heure). Ni CORS ni `WWW-Authenticate` : une page d'un autre site ne l'appelle pas, un
  navigateur ne demande ni ne rejoue un mot de passe ici.
- Pas de « visites max » : le compteur de visites compte la page et son aperçu (une image en fait
  deux), et le fichier se lit par `/dl` ou `/preview` sans passer par la page. Une borne couperait
  l'image de la dernière visite sans rien borner vraiment ; il faudrait un ticket par visite.

## Liens publics, partages et sécurité

- **Mini-sites (`/api/publish`, `/f/…`)** : une page HTML, SVG ou XML publiée garde ses
  scripts, formulaires et fenêtres, mais s'exécute dans une origine opaque
  (`Content-Security-Policy: sandbox allow-scripts …`, sans `allow-same-origin`) : elle ne peut
  lire ni la session de la page d'admin ni appeler l'API à sa place. Conséquence : un mini-site
  ne dispose plus de `localStorage` ni de cookies. Les autres types (PDF, images, vidéos)
  s'affichent comme avant.
- **Partages (`/s/…/preview`)** : une page active n'est qu'affichée, sans aucun script. L'aperçu
  sert le fichier entier et compte une visite, pas un téléchargement : un partage de la page
  d'admin borné en téléchargements reste lisible par lui, jusqu'à son expiration (un lien de l'API
  de liens borné n'a pas d'aperçu).
- **Partage d'un dossier** : le lien télécharge le dossier tel qu'il est au moment du
  téléchargement, en zip. Tout ce qu'on y dépose ensuite (par la page d'admin ou par WebDAV)
  devient visible par quiconque a le lien, jusqu'à son expiration ou sa suppression.
- **Limites d'essais** : 5 tentatives par client et par quart d'heure sur `/api/auth`,
  20 jetons faux sur l'API d'admin, 5 identifiants faux sur WebDAV et son API de liens. Le client est l'adresse
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
`dav_test.go` celui de WebDAV, `davlinks_test.go` celui de l'API de liens, `attack_test.go` les
scénarios de la revue de sécurité.
