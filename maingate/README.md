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

## Sauvegarde

Le dossier `/data` (dans le volume `maingate_data`) contient les
comptes, le secret de session et l'historique. À inclure dans tes
sauvegardes si tu ne veux pas perdre les comptes créés.
