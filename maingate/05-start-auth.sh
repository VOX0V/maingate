#!/bin/sh
set -e
echo "[MainGate] Démarrage du service d'authentification (avec surveillance)..."

# Le volume /data est monté par Docker au démarrage du conteneur — son
# propriétaire dépend de l'hôte, pas de ce qui a été fait au build. On doit
# donc corriger les permissions ici (à chaud), pas dans le Dockerfile, sinon
# l'utilisateur non-root "authapp" ne pourrait pas y écrire.
mkdir -p /data
chown -R authapp:authapp /data

# nginx dépend de ce service via auth_request : s'il plante et ne redémarre
# pas, tout le monde reste bloqué en 401 sans avertissement. Cette boucle
# le relance automatiquement s'il s'arrête pour une raison quelconque.
# su-exec authapp : lance python3 sans privilèges root — ce script parent
# reste root (nécessaire pour le chown ci-dessus et pour que l'entrypoint
# nginx officiel fonctionne), mais le process qui traite les requêtes HTTP,
# lui, n'a aucun privilège superflu.
(
  while true; do
    su-exec authapp python3 /app/auth_app.py
    echo "[MainGate] auth_app.py s'est arrêté de façon inattendue, redémarrage dans 2s..." >&2
    sleep 2
  done
) &
