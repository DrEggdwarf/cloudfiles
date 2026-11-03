# cloudfiles

Cloud personnel de Robin, servi sur `https://cloud.robin-borg.dev` : une page d'admin
(dépôt, tri, tags, recherche, renommage, analyse IA), des liens publics `/f/`, des partages
`/s/` à durée ou nombre d'usages limités, et un accès WebDAV sous `/dav/` pour brancher
n'importe quelle application (iji, rclone, un gestionnaire de fichiers).

Un seul binaire Go (`main.go`, `dav.go`, `davfs.go`, `pathdb.go`) ; les fichiers vivent dans
`FILES_DIR`, ce que le service sait d'eux (liens, partages, descriptions, tags) dans la base
SQLite `DB_PATH`, indexée par chemin relatif.

## Variables d'environnement

| Variable | Rôle |
| --- | --- |
| `ADMIN_PASSWORD` | mot de passe de la page d'admin (Bearer de l'API) |
| `AUTH_TOKEN` | jeton de l'API, seul accepté par `/api/suggest` (extension Firefox) |
| `BASE_URL` | adresse publique, préfixe des liens `/f/` et `/s/` |
| `FILES_DIR` | dossier des fichiers (`/data/files` par défaut) |
| `DB_PATH` | base SQLite (`/data/cloud.db` par défaut) |
| `PORT` | port d'écoute (`8080` par défaut) |
| `ANTHROPIC_API_KEY` | analyse IA des fichiers ; sans elle, `/api/analyze` et `/api/suggest` répondent 503 |
| `DAV_USER` | identifiant WebDAV |
| `DAV_PASSWORD_SHA256` | empreinte SHA-256 (hexadécimal) du mot de passe WebDAV |

Sans `DAV_USER` ni `DAV_PASSWORD_SHA256`, WebDAV est éteint (`/dav/` répond 404) et le reste
fonctionne comme avant. Le mot de passe WebDAV doit différer de `ADMIN_PASSWORD` et
`AUTH_TOKEN`, sinon le service refuse de l'activer.

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
- `COPY` : la copie reprend description et tags, pas les liens ni les partages.

Limites : 512 Mo par fichier (comme le dépôt), `PROPFIND` limité à `Depth: 0` ou `1`
(`infinity` répond 403, l'absence d'en-tête vaut `1`), verrous `LOCK` en mémoire (perdus au
redémarrage), 5 identifiants faux par IP et par quart d'heure avant blocage (429), liens
symboliques ni suivis ni listés. Un fichier lu par `/dav/` dans un navigateur s'affiche dans
un bac à sable (`Content-Security-Policy: sandbox`).

## Générer l'empreinte du mot de passe

Tirer un mot de passe long et aléatoire (il ne sert qu'aux applications), puis en calculer
l'empreinte sans le laisser dans l'historique du shell :

```sh
openssl rand -base64 32                                  # le mot de passe d'application, à garder dans un gestionnaire
read -rs P && printf '%s' "$P" | sha256sum | cut -d' ' -f1; unset P
```

Sous PowerShell :

```powershell
$p = Read-Host -AsSecureString
$b = [Text.Encoding]::UTF8.GetBytes([Net.NetworkCredential]::new('', $p).Password)
-join ([Security.Cryptography.SHA256]::Create().ComputeHash($b) | ForEach-Object { $_.ToString('x2') })
```

L'empreinte va dans `DAV_PASSWORD_SHA256` ; le mot de passe en clair ne quitte pas le
gestionnaire et les applications.

## Développer

```sh
docker run --rm -v "$PWD:/src" -w /src golang:1.22 go test ./...
docker build -t cloudfiles .
```

`routes_test.go` fige le comportement des routes d'origine, `dav_test.go` celui de WebDAV.
