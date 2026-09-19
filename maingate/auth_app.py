"""
Micro-service d'authentification pour MainGate (fluidd + mainsail).

- /login            : formulaire de connexion
- /check            : utilisé par nginx (auth_request) — 200 si session valide, 401 sinon
- /logout           : efface le cookie de session
- /session-info     : JSON {username, is_admin} pour la session en cours (401 sinon)
- /admin            : interface admin (comptes, IP bannies, historique) — admin seulement
- /admin/users/*    : créer / activer-désactiver / supprimer un compte — admin seulement
- /admin/bans/unban : débannir une IP manuellement — admin seulement

Comptes stockés (hachés+salés, PBKDF2) dans /data/users.json.
Bannissement par IP après échecs répétés, stocké dans /data/bans.json.
Historique des tentatives de connexion dans /data/history.json.
Tout est persisté sur le volume /data pour survivre aux redémarrages.

Un seul service sert fluidd (port 80) et mainsail (port 81) via nginx.
Aucune dépendance externe (stdlib uniquement) pour garder l'image légère.

Sécurité :
- Tout texte d'origine utilisateur (nom d'utilisateur, historique de
  connexion) est échappé avant d'être inséré dans le HTML de /admin —
  sans ça, un nom d'utilisateur malveillant soumis sur /login (sans
  authentification requise) pourrait injecter du JavaScript exécuté dans
  le navigateur d'un admin consultant l'historique (XSS stocké).
- Le service tourne sans privilèges (utilisateur dédié, voir Dockerfile) :
  même en cas de faille non prévue ici, l'impact reste limité au conteneur.
"""
import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import stat
import threading
import time
import urllib.parse
from datetime import datetime, timezone

AUTH_USER = os.environ.get("AUTH_USER", "admin")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "changeme")

# https (par défaut) => cookie marqué Secure, jamais envoyé en HTTP simple.
# À mettre à "http" uniquement si aucun TLS n'est en place devant ce service
# (ex. un ami sans Traefik) — sinon le login échouera silencieusement.
CONNECTION_TYPE = os.environ.get("CONNECTION_TYPE", "https").strip().lower()
COOKIE_SECURE = CONNECTION_TYPE != "http"

try:
    BAN_THRESHOLD = int(os.environ.get("BAN_THRESHOLD", "3"))
except ValueError:
    BAN_THRESHOLD = 3
try:
    BAN_DURATION_SECONDS = int(os.environ.get("BAN_DURATION_MINUTES", "60")) * 60
except ValueError:
    BAN_DURATION_SECONDS = 60 * 60
BAN_WINDOW_SECONDS = 10 * 60  # fenêtre glissante pour compter les échecs

DATA_DIR = "/data"
SECRET_PATH = os.path.join(DATA_DIR, "session_secret")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
BANS_PATH = os.path.join(DATA_DIR, "bans.json")
HISTORY_PATH = os.path.join(DATA_DIR, "history.json")
MAX_HISTORY = 500

COOKIE_NAME = "fluidd_session"
SESSION_MAX_AGE = 30 * 24 * 3600  # 30 jours

# Taille max d'un corps de requête POST (formulaires login/admin) — bien
# au-dessus de ce dont un formulaire a besoin, mais empêche un client
# malveillant d'annoncer un Content-Length énorme pour épuiser la mémoire.
MAX_FORM_BYTES = 64 * 1024

_lock = threading.Lock()

# Permissions restrictives (lecture/écriture propriétaire seulement) pour les
# fichiers contenant des secrets ou des hachages de mots de passe.
_PRIVATE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}", flush=True)


# ---------------------------------------------------------------- stockage

def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, _PRIVATE_MODE)
    os.replace(tmp, path)


def get_secret():
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "rb") as f:
            return f.read()
    secret = secrets.token_bytes(32)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SECRET_PATH, "wb") as f:
        f.write(secret)
    os.chmod(SECRET_PATH, _PRIVATE_MODE)
    return secret


SECRET = get_secret()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex(), dk.hex()


def verify_password(password, salt_hex, hash_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# Salt/hash factices utilisés quand le nom d'utilisateur soumis n'existe pas,
# pour que /login prenne un temps comparable à un vrai échec de mot de passe
# (sinon la différence de latence permet de deviner quels comptes existent).
_DUMMY_SALT, _DUMMY_HASH = hash_password(secrets.token_hex(16))


def load_users():
    with _lock:
        return _load_json(USERS_PATH, {})


def save_users(users):
    with _lock:
        _save_json(USERS_PATH, users)


def bootstrap_admin():
    users = load_users()
    if users:
        return
    salt_hex, hash_hex = hash_password(AUTH_PASSWORD)
    users[AUTH_USER] = {
        "salt": salt_hex,
        "hash": hash_hex,
        "is_admin": True,
        "disabled": False,
        "version": 1,
    }
    save_users(users)
    log(f"BOOTSTRAP création du compte admin initial '{AUTH_USER}' depuis AUTH_USER/AUTH_PASSWORD")


def load_bans():
    with _lock:
        return _load_json(BANS_PATH, {})


def save_bans(bans):
    with _lock:
        _save_json(BANS_PATH, bans)


def load_history():
    with _lock:
        return _load_json(HISTORY_PATH, [])


def append_history(ip, user, result):
    with _lock:
        history = _load_json(HISTORY_PATH, [])
        history.append({"ts": int(time.time()), "ip": ip, "user": user, "result": result})
        history = history[-MAX_HISTORY:]
        _save_json(HISTORY_PATH, history)


# ---------------------------------------------------------- bannissement IP

def is_banned(ip):
    bans = load_bans()
    entry = bans.get(ip)
    return bool(entry and entry.get("banned_until", 0) > time.time())


def register_failure(ip):
    bans = load_bans()
    now = int(time.time())
    entry = bans.get(ip, {"count": 0, "first_fail": now, "banned_until": 0})
    if now - entry.get("first_fail", 0) > BAN_WINDOW_SECONDS:
        entry = {"count": 0, "first_fail": now, "banned_until": 0}
    entry["count"] += 1
    if entry["count"] >= BAN_THRESHOLD:
        entry["banned_until"] = now + BAN_DURATION_SECONDS
        entry["count"] = 0
        log(f"BAN ip={ip} durée={BAN_DURATION_SECONDS}s")
    bans[ip] = entry
    save_bans(bans)


def register_success(ip):
    bans = load_bans()
    if ip in bans:
        bans[ip]["count"] = 0
        save_bans(bans)


def unban(ip, admin_user):
    bans = load_bans()
    if ip in bans:
        bans[ip] = {"count": 0, "first_fail": 0, "banned_until": 0}
        save_bans(bans)
        log(f"UNBAN ip={ip} par admin={admin_user}")


# ------------------------------------------------------------------ cookie

def make_cookie_value(username, version):
    expires = int(time.time()) + SESSION_MAX_AGE
    payload = f"{username}:{version}:{expires}".encode()
    sig = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode() + "." + sig


def verify_session(token):
    try:
        payload_b64, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(payload_b64.encode())
        expected_sig = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        user, version, expires = payload.decode().rsplit(":", 2)
        if int(expires) < time.time():
            return None
        users = load_users()
        u = users.get(user)
        if not u or u.get("disabled") or str(u.get("version")) != version:
            return None
        return {"username": user, "is_admin": bool(u.get("is_admin"))}
    except Exception:
        return None


def cookie_header(value, max_age):
    secure = "; Secure" if COOKIE_SECURE else ""
    return f"{COOKIE_NAME}={value}; Path=/; Max-Age={max_age}; HttpOnly{secure}; SameSite=Lax"


# -------------------------------------------------------------------- HTML

PAGE_STYLE = """
body{font-family:sans-serif;background:#1a1a1a;color:#eee;margin:0;padding:1.5rem}
a{color:#63b3ed}
table{width:100%;border-collapse:collapse;margin:.6rem 0 1.4rem}
th,td{padding:.4rem .5rem;border-bottom:1px solid #333;text-align:left;font-size:.9rem}
input,select{padding:.4rem;margin:.2rem 0;border-radius:4px;border:1px solid #444;background:#111;color:#eee}
button{padding:.4rem .8rem;border:none;border-radius:4px;background:#2b6cb0;color:#fff;cursor:pointer}
button.danger{background:#c53030}
.msg{background:#2d3748;padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem}
.tag{padding:.1rem .4rem;border-radius:3px;font-size:.75rem}
.tag.admin{background:#2b6cb0}
.tag.disabled{background:#c53030}
.tag.ok{background:#2f855a}
.tag.fail{background:#c53030}
.tag.banned{background:#744210}
"""

LOGIN_FORM = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connexion — MainGate</title>
<style>
body{{font-family:sans-serif;background:#1a1a1a;color:#eee;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}}
form{{background:#242424;padding:2rem;border-radius:8px;min-width:280px}}
input{{width:100%;padding:.6rem;margin:.4rem 0;box-sizing:border-box;
border-radius:4px;border:1px solid #444;background:#111;color:#eee}}
button{{width:100%;padding:.6rem;margin-top:.6rem;border:none;border-radius:4px;
background:#2b6cb0;color:#fff;font-weight:bold}}
.err{{color:#e57373;margin-bottom:.5rem}}
</style></head><body>
<form method="POST" action="/login">
<h2>Connexion</h2>
{error}
<input name="username" placeholder="Utilisateur" autocomplete="username" required>
<input name="password" type="password" placeholder="Mot de passe" autocomplete="current-password" required>
<button type="submit">Se connecter</button>
</form></body></html>"""

BANNED_PAGE = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Accès temporairement bloqué</title>
<style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}}
div{{background:#242424;padding:2rem;border-radius:8px}}</style></head><body>
<div><h2>Trop de tentatives</h2>
<p>Cette adresse IP est temporairement bloquée suite à plusieurs échecs de connexion.</p>
<p>Réessaie plus tard.</p></div></body></html>"""


def render_admin(current, users, bans, history, message=None):
    now = int(time.time())
    msg_html = f'<div class="msg">{html.escape(message)}</div>' if message else ""

    rows_users = ""
    admin_count = sum(1 for u in users.values() if u.get("is_admin") and not u.get("disabled"))
    for uname, u in sorted(users.items()):
        safe_uname = html.escape(uname)
        tags = ""
        if u.get("is_admin"):
            tags += '<span class="tag admin">admin</span> '
        if u.get("disabled"):
            tags += '<span class="tag disabled">désactivé</span>'
        is_last_admin = u.get("is_admin") and not u.get("disabled") and admin_count <= 1
        toggle_label = "Réactiver" if u.get("disabled") else "Désactiver"
        toggle_btn = (
            f'<button class="danger" formaction="/admin/users/toggle" name="username" value="{safe_uname}">{toggle_label}</button>'
            if not is_last_admin or u.get("disabled")
            else '<span style="color:#888">dernier admin</span>'
        )
        delete_btn = (
            f'<button class="danger" formaction="/admin/users/delete" name="username" value="{safe_uname}" '
            f'onclick="return confirm(&#39;Supprimer {safe_uname} ?&#39;)">Supprimer</button>'
            if not is_last_admin
            else ""
        )
        rows_users += (
            f"<tr><td>{safe_uname} {tags}</td><td>"
            f'<form method="POST" style="display:inline">{toggle_btn} {delete_btn}</form>'
            f"</td></tr>"
        )

    rows_bans = ""
    for ip, entry in sorted(bans.items()):
        if entry.get("banned_until", 0) > now:
            remaining = entry["banned_until"] - now
            safe_ip = html.escape(ip)
            rows_bans += (
                f"<tr><td>{safe_ip}</td><td>encore {remaining // 60} min</td>"
                f'<td><form method="POST" action="/admin/bans/unban" style="display:inline">'
                f'<button name="ip" value="{safe_ip}">Débannir</button></form></td></tr>'
            )
    if not rows_bans:
        rows_bans = '<tr><td colspan="3" style="color:#888">Aucune IP bannie actuellement</td></tr>'

    rows_hist = ""
    for entry in reversed(history[-50:]):
        dt = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        tag_class = {"success": "ok", "fail": "fail", "banned": "banned"}.get(entry["result"], "")
        safe_user = html.escape(entry.get("user") or "—")
        safe_ip = html.escape(entry["ip"])
        safe_result = html.escape(entry["result"])
        rows_hist += (
            f"<tr><td>{dt}</td><td>{safe_user}</td><td>{safe_ip}</td>"
            f'<td><span class="tag {tag_class}">{safe_result}</span></td></tr>'
        )

    safe_current_user = html.escape(current["username"])

    return f"""<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Administration — MainGate</title><style>{PAGE_STYLE}</style></head><body>
<h2>Administration — MainGate</h2>
<p>Connecté en tant que <b>{safe_current_user}</b> — <a href="/logout">Déconnexion</a> — <a href="/">Retour à l'app</a></p>
{msg_html}

<h3>Comptes</h3>
<table><tr><th>Utilisateur</th><th>Actions</th></tr>{rows_users}</table>
<form method="POST" action="/admin/users/create">
<input name="username" placeholder="Nouvel utilisateur" required>
<input name="password" type="password" placeholder="Mot de passe" required>
<label><input type="checkbox" name="is_admin"> Admin</label>
<button type="submit">Créer</button>
</form>

<h3>IP bannies</h3>
<table><tr><th>IP</th><th>Durée restante</th><th></th></tr>{rows_bans}</table>

<h3>Historique récent (50 dernières entrées)</h3>
<table><tr><th>Date</th><th>Utilisateur</th><th>IP</th><th>Résultat</th></tr>{rows_hist}</table>
</body></html>"""


# ------------------------------------------------------------------- HTTP

class Handler(http.server.BaseHTTPRequestHandler):
    # Évite qu'une connexion lente/à moitié ouverte ne bloque un thread
    # indéfiniment (chaque requête est traitée dans son propre thread par
    # ThreadingHTTPServer, mais un timeout reste une protection utile).
    timeout = 15

    def log_message(self, fmt, *args):
        pass  # on log nous-mêmes ce qui est pertinent (voir log())

    def _cookies(self):
        cookie_header_val = self.headers.get("Cookie", "")
        cookies = {}
        for part in cookie_header_val.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        return cookies

    def _client_ip(self):
        # Priorité à CF-Connecting-IP (ajouté uniquement par Cloudflare, avec
        # la vraie IP du visiteur) — le plus fiable quand Cloudflare est
        # devant. Sinon on retombe sur la première IP de X-Forwarded-For
        # (premier maillon de la chaîne = client d'origine), puis sur
        # l'adresse de connexion directe. Aucune IP d'infrastructure n'est
        # codée en dur ici : ça marche pareil quel que soit le reverse proxy
        # utilisé devant ce service.
        return (
            self.headers.get("CF-Connecting-IP")
            or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or self.client_address[0]
        )

    def _session(self):
        token = self._cookies().get(COOKIE_NAME, "")
        return verify_session(token) if token else None

    def _send_html(self, status, body, clear_site_data=False):
        body_bytes = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        if clear_site_data:
            # Force le navigateur à vider le cache/service worker/storage de
            # Fluidd (PWA) — évite qu'il réaffiche une app périmée depuis son
            # cache alors que la session n'est plus valide (voir /login).
            self.send_header("Clear-Site-Data", '"cache", "cookies", "storage"')
        self.end_headers()
        self.wfile.write(body_bytes)

    def _redirect(self, location, extra_headers=None):
        self.send_response(303)
        self.send_header("Location", location)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _reject_too_large(self):
        self.send_response(413)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        return urllib.parse.parse_qs(body)

    def _require_admin(self):
        session = self._session()
        if not session:
            self._redirect("/login")
            return None
        if not session["is_admin"]:
            self._send_html(403, "<h2>Accès refusé</h2><p>Réservé aux comptes administrateur.</p>")
            return None
        return session

    # -------------------------------------------------------------- GET

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        ip = self._client_ip()

        if path == "/check":
            self.send_response(200 if self._session() else 401)
            self.end_headers()
            return

        if path == "/login":
            if is_banned(ip):
                self._send_html(403, BANNED_PAGE, clear_site_data=True)
                return
            self._send_html(200, LOGIN_FORM.format(error=""), clear_site_data=True)
            return

        if path == "/logout":
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", cookie_header("", 0))
            self.end_headers()
            return

        if path == "/admin":
            session = self._require_admin()
            if not session:
                return
            self._send_html(200, render_admin(session, load_users(), load_bans(), load_history()))
            return

        if path == "/session-info":
            session = self._session()
            if not session:
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({"username": session["username"], "is_admin": session["is_admin"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    # ------------------------------------------------------------- POST

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        ip = self._client_ip()

        # Rejette d'emblée un corps de requête anormalement gros (avant même
        # de le lire) — protège contre un client qui annoncerait un
        # Content-Length énorme pour épuiser la mémoire du service.
        try:
            declared_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            declared_length = 0
        if declared_length > MAX_FORM_BYTES:
            self._reject_too_large()
            return

        if path == "/login":
            if is_banned(ip):
                self._send_html(403, BANNED_PAGE, clear_site_data=True)
                return
            data = self._read_form()
            user = data.get("username", [""])[0]
            pwd = data.get("password", [""])[0]
            users = load_users()
            u = users.get(user)
            if u:
                ok = (not u.get("disabled")) and verify_password(pwd, u["salt"], u["hash"])
            else:
                # Calcule quand même un hachage factice : évite qu'un
                # attaquant distingue "compte inexistant" de "mauvais mot de
                # passe" en mesurant le temps de réponse (énumération de
                # comptes par timing).
                verify_password(pwd, _DUMMY_SALT, _DUMMY_HASH)
                ok = False
            if ok:
                register_success(ip)
                append_history(ip, user, "success")
                log(f"LOGIN succès user={user} ip={ip}")
                token = make_cookie_value(user, u.get("version", 1))
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", cookie_header(token, SESSION_MAX_AGE))
                self.end_headers()
            else:
                register_failure(ip)
                append_history(ip, user or None, "fail")
                log(f"LOGIN échec user={user!r} ip={ip}")
                if is_banned(ip):
                    self._send_html(403, BANNED_PAGE, clear_site_data=True)
                else:
                    self._send_html(401, LOGIN_FORM.format(error='<div class="err">Identifiants incorrects</div>'), clear_site_data=True)
            return

        if path == "/admin/users/create":
            session = self._require_admin()
            if not session:
                return
            data = self._read_form()
            uname = data.get("username", [""])[0].strip()
            pwd = data.get("password", [""])[0]
            is_admin = data.get("is_admin", [""])[0] == "on"
            users = load_users()
            message = None
            if not uname or ":" in uname:
                message = "Nom d'utilisateur invalide (vide ou contient ':')."
            elif uname in users:
                message = f"Le compte '{uname}' existe déjà."
            elif not pwd:
                message = "Mot de passe requis."
            else:
                salt_hex, hash_hex = hash_password(pwd)
                users[uname] = {"salt": salt_hex, "hash": hash_hex, "is_admin": is_admin, "disabled": False, "version": 1}
                save_users(users)
                log(f"ADMIN {session['username']} a créé le compte '{uname}' (admin={is_admin})")
                message = f"Compte '{uname}' créé."
            self._send_html(200, render_admin(session, load_users(), load_bans(), load_history(), message))
            return

        if path == "/admin/users/toggle":
            session = self._require_admin()
            if not session:
                return
            data = self._read_form()
            uname = data.get("username", [""])[0]
            users = load_users()
            message = None
            if uname in users:
                u = users[uname]
                admin_count = sum(1 for x in users.values() if x.get("is_admin") and not x.get("disabled"))
                if u.get("is_admin") and not u.get("disabled") and admin_count <= 1:
                    message = "Impossible : c'est le dernier compte admin actif."
                else:
                    u["disabled"] = not u.get("disabled")
                    u["version"] = u.get("version", 1) + 1  # révoque les sessions déjà ouvertes
                    save_users(users)
                    log(f"ADMIN {session['username']} a {'désactivé' if u['disabled'] else 'réactivé'} '{uname}'")
                    message = f"Compte '{uname}' {'désactivé' if u['disabled'] else 'réactivé'}."
            self._send_html(200, render_admin(session, load_users(), load_bans(), load_history(), message))
            return

        if path == "/admin/users/delete":
            session = self._require_admin()
            if not session:
                return
            data = self._read_form()
            uname = data.get("username", [""])[0]
            users = load_users()
            message = None
            if uname in users:
                admin_count = sum(1 for x in users.values() if x.get("is_admin") and not x.get("disabled"))
                if users[uname].get("is_admin") and not users[uname].get("disabled") and admin_count <= 1:
                    message = "Impossible : c'est le dernier compte admin actif."
                else:
                    del users[uname]
                    save_users(users)
                    log(f"ADMIN {session['username']} a supprimé le compte '{uname}'")
                    message = f"Compte '{uname}' supprimé."
            self._send_html(200, render_admin(session, load_users(), load_bans(), load_history(), message))
            return

        if path == "/admin/bans/unban":
            session = self._require_admin()
            if not session:
                return
            data = self._read_form()
            target_ip = data.get("ip", [""])[0]
            unban(target_ip, session["username"])
            self._send_html(200, render_admin(session, load_users(), load_bans(), load_history(), f"IP {target_ip} débannie."))
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    bootstrap_admin()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 9000), Handler)
    server.daemon_threads = True
    server.serve_forever()
