# MainGate

Accès distant sécurisé à Fluidd et Mainsail (Klipper/Moonraker), dans un
seul conteneur Docker : authentification par comptes, bannissement
automatique d'IP après échecs répétés, HTTPS en amont recommandé.

## Déploiement

1. Remplis le fichier `.env` (à la racine du projet) :
   - `MOONRAKER_HOST` / `MOONRAKER_PORT` : IP/port de Moonraker (souvent
     `127.0.0.1:7125` si Klipper tourne sur la même machine, sinon l'IP LAN)
   - `WEBCAM_HOST` / `WEBCAM_PORT` : IP/port du flux webcam (Crowsnest, MJPG-streamer, etc.)
   - `AUTH_USER` / `AUTH_PASSWORD` : identifiants du **premier** compte
     admin, créés automatiquement au premier démarrage seulement. Une fois
     ce compte créé, la gestion des comptes se fait via `/admin` — ces deux
     valeurs ne sont plus relues ensuite.
   - `CONNECTION_TYPE` : **`https`** si ce conteneur est accédé via un reverse
     proxy TLS (Traefik, nginx, Caddy...) — cas normal et recommandé.
     **`http`** UNIQUEMENT si aucun TLS n'est en place devant ce service
     (déconseillé, voir avertissement plus bas).
   - `BAN_THRESHOLD` / `BAN_DURATION_MINUTES` : nombre d'échecs de connexion
     avant bannissement d'une IP, et durée du bannissement.

2. Démarre le service :
   ```
   docker compose up -d --build
   ```

3. Fluidd est servi sur le port `FLUIDD_REMOTE_PORT` (8090 par défaut),
   Mainsail sur `MAINSAIL_REMOTE_PORT` (8091 par défaut). Connecte-toi avec
   le compte admin défini à l'étape 1.

4. Va sur `/admin` (ex. `https://tondomaine.tld/admin`) pour créer d'autres
   comptes, consulter l'historique de connexion ou débannir une IP.

## ⚠️ Avertissement important sur `CONNECTION_TYPE`

Ce service n'est prévu que pour être exposé **derrière un reverse proxy qui
termine le TLS** (Traefik, nginx, Caddy, etc.) — c'est ce que fait
`CONNECTION_TYPE=https`. Si tu exposes ce conteneur directement sur
Internet **sans** TLS devant (`CONNECTION_TYPE=http`), les mots de passe et
cookies de session circulent en clair sur le réseau — n'importe qui en
mesure d'intercepter le trafic (réseau public, FAI, etc.) peut les lire.
Utilise `http` seulement en test local, ou en attendant de mettre un
reverse proxy TLS en place.

## Sécurité en place

- Comptes multi-utilisateurs, mots de passe hachés+salés (PBKDF2), jamais
  stockés en clair
- Bannissement automatique d'IP après échecs répétés (configurable),
  persistant entre redémarrages
- Cookies de session signés (HMAC), révoqués immédiatement à la
  désactivation d'un compte
- Rate-limiting supplémentaire au niveau nginx sur `/login`
- Le service d'authentification se relance automatiquement s'il plante
- Toutes les tentatives de connexion et actions admin sont journalisées
  (`docker logs MainGate`)

## API de statut (réseau local)

Lecture seule, sans login, publiée sur `API_PORT` (8092 par défaut) et
limitée aux IP locales (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`). Ne l'expose jamais via un reverse proxy ni une
redirection de port depuis Internet : le filtre se base sur l'IP source
vue par le conteneur.

- `GET /status` : vue organisée — `klippy`, `print` (état, fichier,
  progression, temps écoulé/restant, filament utilisé, couches),
  `temperatures`, `fans`, `filament_sensors`, `toolhead`, `gcode_move`,
  `motion_report`, `idle_timeout`, `system_stats`, `host`, `history_totals`
- `GET /status/raw` : tous les objets Klipper bruts (sans `configfile` ni
  les macros)
- Réponse `503` si Moonraker est injoignable

Champs calculés par l'API : `time_remaining_s` (selon la progression du
fichier), `time_remaining_slicer_s` (estimation du slicer moins le temps
écoulé), `eta_epoch`, `filament_used_m`, `filament_estimated_remaining_mm`.
`current_layer_estimated` (déduite de la hauteur Z : approximative avec
z-hop ou vase mode), `filament_used_g_estimated` (poids total du fichier ×
part de filament consommée), `cost_used` et `cost_total_estimated`
(poids × prix) et `time_remaining_min`. Le bloc `display` contient des
textes prêts à afficher dans un widget (`progress`, `elapsed`, `remaining`,
`layer`, `extruder`, `bed`, `filament`, `weight`, `cost`). Les autres
valeurs viennent telles quelles de Klipper/Moonraker.

Les capteurs sans valeur (ex. drivers TMC) sont omis de `temperatures`, et
`host` ne garde que le dernier relevé et les interfaces réseau physiques
(`eth*`, `en*`, `wl*`).

**Prix du filament** : à régler dans `/admin`, section « Réglages » ($/kg,
stocké dans `/data/settings.json`). Sans prix, `cost_used`,
`cost_total_estimated` et `price_per_kg` valent `null`.

## Sauvegarde

Le dossier `/data` (dans le volume `maingate_data`) contient les
comptes, le secret de session et l'historique. À inclure dans tes
sauvegardes si tu ne veux pas perdre les comptes créés.
