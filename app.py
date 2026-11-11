# pyright: reportMissingImports=false
import os
import secrets
import sqlite3
from functools import wraps

import flask
from werkzeug.security import check_password_hash, generate_password_hash

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
DB_PATH = os.path.join(app.root_path, "hackhub.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


# ---------- database ----------
def get_db():
    if "db" not in flask.g:
        flask.g.db = sqlite3.connect(DB_PATH)
        flask.g.db.row_factory = sqlite3.Row
        flask.g.db.execute("PRAGMA foreign_keys = ON")
    return flask.g.db


@app.teardown_appcontext
def close_db(_exc):
    db = flask.g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    with open(os.path.join(app.root_path, "schema.sql")) as f:
        db.executescript(f.read())
    for name in ("admin1", "admin2", "admin3"):  # exactly 3 default admins
        if not db.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
            db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (name, name, generate_password_hash(ADMIN_PASSWORD)),
            )
    db.commit()
    db.close()


# ---------- request helpers ----------
@app.before_request
def load_user_and_check_csrf():
    uid = flask.session.get("user_id")
    flask.g.user = None
    if uid:
        flask.g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if flask.g.user is None:
            flask.session.clear()
    if flask.request.method == "POST":
        sent, expected = flask.request.form.get("csrf_token", ""), flask.session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            flask.abort(400, "Invalid or missing CSRF token")


@app.context_processor
def inject_globals():
    if "csrf_token" not in flask.session:
        flask.session["csrf_token"] = secrets.token_hex(16)
    return {"csrf_token": flask.session["csrf_token"], "user": flask.g.get("user")}


def login_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if flask.g.user is None:
                flask.flash("Please log in first.", "error")
                return flask.redirect(flask.url_for("login"))
            if roles and flask.g.user["role"] not in roles:
                flask.abort(403)
            return view(*a, **kw)
        return wrapped
    return deco


def home_for(user):
    return flask.url_for({"admin": "admin_panel", "host": "host_dashboard"}.get(user["role"], "hackathons"))


def get_hackathon_or_404(hid):
    h = get_db().execute(
        "SELECT h.*, u.username AS host_name FROM hackathons h JOIN users u ON u.id = h.host_id WHERE h.id = ?",
        (hid,),
    ).fetchone()
    if h is None:
        flask.abort(404)
    return h


def can_manage(h):
    return flask.g.user["role"] == "admin" or (flask.g.user["role"] == "host" and h["host_id"] == flask.g.user["id"])


# ---------- public + auth ----------
@app.route("/")
def index():
    return flask.render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if flask.g.user:
        return flask.redirect(home_for(flask.g.user))
    if flask.request.method == "POST":
        username = flask.request.form.get("username", "").strip()
        email = flask.request.form.get("email", "").strip().lower()
        password = flask.request.form.get("password", "")
        role = flask.request.form.get("role", "")
        error = None
        if not 3 <= len(username) <= 30 or not username.replace("_", "").replace(".", "").isalnum():
            error = "Username must be 3–30 characters: letters, numbers, dots or underscores."
        elif "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email address."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif role not in ("host", "participant"):
            error = "Choose a role: Host or Participant."
        if error is None:
            try:
                db = get_db()
                cur = db.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), role),
                )
                db.commit()
                flask.session.clear()
                flask.session["user_id"] = cur.lastrowid
                flask.flash(f"Welcome to HackHub, {username}!", "ok")
                return flask.redirect(flask.url_for("dashboard"))
            except sqlite3.IntegrityError:
                error = "That username or email is already registered."
        flask.flash(error, "error")
    return flask.render_template("register.html", form=flask.request.form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if flask.g.user:
        return flask.redirect(home_for(flask.g.user))
    if flask.request.method == "POST":
        ident = flask.request.form.get("identifier", "").strip()
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (ident, ident)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], flask.request.form.get("password", "")):
            flask.session.clear()
            flask.session["user_id"] = row["id"]
            return flask.redirect(flask.url_for("dashboard"))
        flask.flash("Wrong username/email or password.", "error")
    return flask.render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    flask.session.clear()
    flask.flash("You're logged out.", "ok")
    return flask.redirect(flask.url_for("index"))


@app.route("/dashboard")
@login_required()
def dashboard():
    return flask.redirect(home_for(flask.g.user))


# ---------- hackathons (shared) ----------
@app.route("/hackathons")
@login_required()
def hackathons():
    rows = get_db().execute(
        """SELECT h.*, u.username AS host_name,
                  (SELECT COUNT(*) FROM applications a WHERE a.hackathon_id = h.id) AS app_count
           FROM hackathons h JOIN users u ON u.id = h.host_id
           ORDER BY h.created_at DESC, h.id DESC"""
    ).fetchall()
    return flask.render_template("hackathons.html", hackathons=rows)


@app.route("/hackathons/<int:hid>")
@login_required()
def hackathon_detail(hid):
    h = get_hackathon_or_404(hid)
    applied = None
    if flask.g.user["role"] == "participant":
        applied = get_db().execute(
            "SELECT id FROM applications WHERE hackathon_id = ? AND applicant_id = ?", (hid, flask.g.user["id"])
        ).fetchone()
    return flask.render_template("hackathon_detail.html", h=h, applied=applied, can_manage=can_manage(h))


# ---------- host ----------
def read_hackathon_form():
    data = {k: flask.request.form.get(k, "").strip() for k in ("name", "domains", "duration", "start_date", "terms", "notes")}
    required = ("name", "domains", "duration", "start_date", "terms")
    return data, [k for k in required if not data[k]]


@app.route("/host")
@login_required("host")
def host_dashboard():
    rows = get_db().execute(
        """SELECT h.*, (SELECT COUNT(*) FROM applications a WHERE a.hackathon_id = h.id) AS app_count
           FROM hackathons h WHERE h.host_id = ? ORDER BY h.created_at DESC""",
        (flask.g.user["id"],),
    ).fetchall()
    return flask.render_template("host_dashboard.html", hackathons=rows)


@app.route("/host/create", methods=["GET", "POST"])
@login_required("host", "admin")
def create_hackathon():
    if flask.request.method == "POST":
        data, missing = read_hackathon_form()
        if missing:
            flask.flash("Please fill in: " + ", ".join(missing).replace("_", " ") + ".", "error")
            return flask.render_template("hackathon_form.html", h=data, editing=False)
        db = get_db()
        cur = db.execute(
            """INSERT INTO hackathons (host_id, name, domains, duration, start_date, terms, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (flask.g.user["id"], data["name"], data["domains"], data["duration"], data["start_date"], data["terms"], data["notes"]),
        )
        db.commit()
        flask.flash("Hackathon published. Every participant can see it now.", "ok")
        return flask.redirect(flask.url_for("hackathon_detail", hid=cur.lastrowid))
    return flask.render_template("hackathon_form.html", h={}, editing=False)


@app.route("/hackathons/<int:hid>/edit", methods=["GET", "POST"])
@login_required("host", "admin")
def edit_hackathon(hid):
    h = get_hackathon_or_404(hid)
    if not can_manage(h):
        flask.abort(403)
    if flask.request.method == "POST":
        data, missing = read_hackathon_form()
        if missing:
            flask.flash("Please fill in: " + ", ".join(missing).replace("_", " ") + ".", "error")
            return flask.render_template("hackathon_form.html", h={**data, "id": hid}, editing=True)
        db = get_db()
        db.execute(
            "UPDATE hackathons SET name=?, domains=?, duration=?, start_date=?, terms=?, notes=? WHERE id=?",
            (data["name"], data["domains"], data["duration"], data["start_date"], data["terms"], data["notes"], hid),
        )
        db.commit()
        flask.flash("Hackathon saved.", "ok")
        return flask.redirect(flask.url_for("hackathon_detail", hid=hid))
    return flask.render_template("hackathon_form.html", h=h, editing=True)


@app.route("/hackathons/<int:hid>/delete", methods=["POST"])
@login_required("host", "admin")
def delete_hackathon(hid):
    h = get_hackathon_or_404(hid)
    if not can_manage(h):
        flask.abort(403)
    db = get_db()
    db.execute("DELETE FROM hackathons WHERE id = ?", (hid,))
    db.commit()
    flask.flash("Hackathon deleted.", "ok")
    return flask.redirect(home_for(flask.g.user))


@app.route("/hackathons/<int:hid>/applications")
@login_required("host", "admin")
def hackathon_applications(hid):
    h = get_hackathon_or_404(hid)
    if not can_manage(h):
        flask.abort(403)
    apps = get_db().execute(
        "SELECT * FROM applications WHERE hackathon_id = ? ORDER BY created_at DESC", (hid,)
    ).fetchall()
    return flask.render_template("applications.html", h=h, apps=apps)


@app.route("/applications/<int:aid>/delete", methods=["POST"])
@login_required("host", "admin")
def delete_application(aid):
    db = get_db()
    a = db.execute("SELECT * FROM applications WHERE id = ?", (aid,)).fetchone()
    if a is None:
        flask.abort(404)
    if not can_manage(get_hackathon_or_404(a["hackathon_id"])):
        flask.abort(403)
    db.execute("DELETE FROM applications WHERE id = ?", (aid,))
    db.commit()
    flask.flash("Application removed.", "ok")
    return flask.redirect(flask.url_for("hackathon_applications", hid=a["hackathon_id"]))


# ---------- participant ----------
def split_csv(text):
    return [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]


@app.route("/hackathons/<int:hid>/apply", methods=["GET", "POST"])
@login_required("participant")
def apply(hid):
    h = get_hackathon_or_404(hid)
    db = get_db()
    if db.execute("SELECT 1 FROM applications WHERE hackathon_id=? AND applicant_id=?", (hid, flask.g.user["id"])).fetchone():
        flask.flash("You've already applied to this hackathon.", "error")
        return flask.redirect(flask.url_for("hackathon_detail", hid=hid))
    domains = split_csv(h["domains"])
    if flask.request.method == "POST":
        f = {k: flask.request.form.get(k, "").strip() for k in
             ("participant_username", "team_members", "institutions", "team_name", "team_leader", "project_name", "domain")}
        error = None
        if not all(f.values()):
            error = "Every field is required."
        elif f["domain"] not in domains:
            error = "Pick one of the hackathon's domains."
        else:
            members = split_csv(f["team_members"])
            known = {r["username"].lower() for r in db.execute("SELECT username FROM users WHERE role='participant'")}
            unknown = [m for m in members if m.lower() not in known]
            if unknown:
                error = "These team members aren't registered participants: " + ", ".join(unknown)
        if error is None:
            try:
                db.execute(
                    """INSERT INTO applications (hackathon_id, applicant_id, participant_username, team_members,
                       institutions, team_name, team_leader, project_name, domain) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (hid, flask.g.user["id"], f["participant_username"], ", ".join(split_csv(f["team_members"])),
                     f["institutions"], f["team_name"], f["team_leader"], f["project_name"], f["domain"]),
                )
                db.commit()
                flask.flash(f"Application sent to {h['host_name']}. Good luck!", "ok")
                return flask.redirect(flask.url_for("my_applications"))
            except sqlite3.IntegrityError:
                error = "You've already applied to this hackathon."
        flask.flash(error, "error")
        return flask.render_template("apply.html", h=h, domains=domains, form=f)
    return flask.render_template("apply.html", h=h, domains=domains, form={"participant_username": flask.g.user["username"]})


@app.route("/my-applications")
@login_required("participant")
def my_applications():
    rows = get_db().execute(
        """SELECT a.*, h.name AS hackathon_name FROM applications a
           JOIN hackathons h ON h.id = a.hackathon_id WHERE a.applicant_id = ? ORDER BY a.created_at DESC""",
        (flask.g.user["id"],),
    ).fetchall()
    return flask.render_template("my_applications.html", apps=rows)


# ---------- admin ----------
@app.route("/admin")
@login_required("admin")
def admin_panel():
    db = get_db()
    return flask.render_template(
        "admin.html",
        users=db.execute("SELECT * FROM users ORDER BY role, username").fetchall(),
        hackathons=db.execute(
            """SELECT h.*, u.username AS host_name,
                      (SELECT COUNT(*) FROM applications a WHERE a.hackathon_id = h.id) AS app_count
               FROM hackathons h JOIN users u ON u.id = h.host_id ORDER BY h.id DESC"""
        ).fetchall(),
    )


@app.route("/admin/users/<int:uid>/update", methods=["POST"])
@login_required("admin")
def admin_update_user(uid):
    db = get_db()
    role = flask.request.form.get("role")
    password = flask.request.form.get("password", "")
    if role not in ("host", "participant", "admin"):
        flask.abort(400)
    if uid == flask.g.user["id"] and role != "admin":
        flask.flash("You can't remove your own admin role.", "error")
        return flask.redirect(flask.url_for("admin_panel"))
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
    if password:
        if len(password) < 6:
            flask.flash("Password must be at least 6 characters.", "error")
            return flask.redirect(flask.url_for("admin_panel"))
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), uid))
    db.commit()
    flask.flash("User updated.", "ok")
    return flask.redirect(flask.url_for("admin_panel"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_user(uid):
    if uid == flask.g.user["id"]:
        flask.flash("You can't delete your own account.", "error")
    else:
        db = get_db()
        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        db.commit()
        flask.flash("User deleted (their hackathons and applications went with them).", "ok")
    return flask.redirect(flask.url_for("admin_panel"))


@app.errorhandler(403)
def forbidden(_e):
    return flask.render_template("error.html", code=403, msg="You don't have access to this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return flask.render_template("error.html", code=404, msg="We couldn't find that page."), 404


init_db()

if __name__ == "__main__":
    app.run(debug=True)
