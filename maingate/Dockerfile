FROM nginx:1.27-alpine

# Récupère les dernières releases statiques de Fluidd et Mainsail (webUIs)
# et les place chacune dans leur propre racine servie par nginx. Installe
# aussi python3 (micro-service de login) et su-exec (pour le lancer sans
# privilèges root, voir 05-start-auth.sh). Le -f de curl fait échouer le
# build proprement si GitHub renvoie une erreur, plutôt que d'essayer de
# dézipper une page d'erreur HTML silencieusement.
RUN apk add --no-cache curl unzip \
    && curl -fsSL "https://github.com/fluidd-core/fluidd/releases/latest/download/fluidd.zip" -o /tmp/fluidd.zip \
    && rm -rf /usr/share/nginx/html && mkdir -p /usr/share/nginx/html \
    && unzip -oq /tmp/fluidd.zip -d /usr/share/nginx/html \
    && rm /tmp/fluidd.zip \
    && curl -fsSL "https://github.com/mainsail-crew/mainsail/releases/latest/download/mainsail.zip" -o /tmp/mainsail.zip \
    && rm -rf /usr/share/nginx/mainsail && mkdir -p /usr/share/nginx/mainsail \
    && unzip -oq /tmp/mainsail.zip -d /usr/share/nginx/mainsail \
    && rm /tmp/mainsail.zip \
    && apk del curl unzip \
    && apk add --no-cache python3 su-exec \
    && addgroup -S authapp && adduser -S -G authapp authapp

# Template nginx traité automatiquement par l'image officielle via envsubst
# au démarrage (fonctionnalité native depuis nginx:1.19+), généré vers
# /etc/nginx/conf.d/default.conf
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Script exécuté automatiquement au démarrage (mécanisme natif de l'image
# nginx officielle : tout script exécutable dans /docker-entrypoint.d/ est
# lancé avant nginx, dans l'ordre alphabétique)
#   05-start-auth.sh : lance le micro-service de login en arrière-plan
#                      (sous l'utilisateur non-root "authapp"), et le
#                      relance automatiquement s'il crash
COPY 05-start-auth.sh /docker-entrypoint.d/05-start-auth.sh
RUN chmod +x /docker-entrypoint.d/05-start-auth.sh

# Micro-service de login (page de connexion + cookie de session). Appartient
# à "authapp" : le process tourne sans privilèges, donc pas besoin d'accès
# root aux fichiers qu'il lit.
COPY auth_app.py /app/auth_app.py
RUN chown -R authapp:authapp /app

# Valeurs par défaut génériques — à écraser via docker-compose.yml / .env.
# MOONRAKER_HOST/WEBCAM_HOST par défaut à 127.0.0.1 (cas où Moonraker tourne
# sur la même machine que ce conteneur) : jamais d'IP personnelle codée en
# dur dans une image destinée à être publiée et réutilisée par d'autres.
ENV MOONRAKER_HOST=127.0.0.1 \
    MOONRAKER_PORT=7125 \
    WEBCAM_HOST=127.0.0.1 \
    WEBCAM_PORT=8080 \
    AUTH_USER=admin \
    AUTH_PASSWORD=changeme \
    CONNECTION_TYPE=https \
    BAN_THRESHOLD=3 \
    BAN_DURATION_MINUTES=60 \
    NGINX_ENVSUBST_FILTER=^(MOONRAKER_HOST|MOONRAKER_PORT|WEBCAM_HOST|WEBCAM_PORT)$

EXPOSE 80 81

# Vérifie nginx sur les deux sites (fluidd:80, mainsail:81) ET le
# micro-service d'auth (9000) — un healthcheck qui ne testait que nginx
# ne détecterait pas un auth_app.py planté (tout le monde bloqué en 401).
# Forme JSON avec "sh -c" (plutôt que la forme shell implicite) : permet de
# chaîner les trois vérifications avec && / || tout en suivant la notation
# recommandée pour CMD/HEALTHCHECK.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["sh", "-c", "wget -qO- http://127.0.0.1/login >/dev/null 2>&1 && wget -qO- http://127.0.0.1:81/login >/dev/null 2>&1 && wget -qO- http://127.0.0.1:9000/login >/dev/null 2>&1 || exit 1"]
