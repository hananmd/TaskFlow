import json
import os
import sqlite3
from datetime import date, datetime

from cryptography.fernet import Fernet
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from werkzeug.security import check_password_hash, generate_password_hash

# ── App & persistent secrets ──────────────────────────────────────────────────
app = Flask(__name__)

_SECRETS_FILE = "secrets.json"
if os.path.exists(_SECRETS_FILE):
    with open(_SECRETS_FILE) as _f:
        _s = json.load(_f)
else:
    _s = {
        "flask_secret": os.urandom(32).hex(),
        "fernet_key": Fernet.generate_key().decode(),
    }
    with open(_SECRETS_FILE, "w") as _f:
        json.dump(_s, _f)

app.secret_key = bytes.fromhex(_s["flask_secret"])
_fernet = Fernet(_s["fernet_key"].encode())


def encrypt(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet.decrypt(token.encode()).decode()
    except Exception:
        return ""


# ── Database ──────────────────────────────────────────────────────────────────
DB = "todos.db"
_PRIORITY_ORDER = "CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        # Drop old schema (no user_id column) and recreate
        has_users = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if not has_users:
            conn.execute("DROP TABLE IF EXISTS todos")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                email         TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                theme         TEXT    NOT NULL DEFAULT 'light',
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS todos (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                title      TEXT    NOT NULL,
                done       INTEGER NOT NULL DEFAULT 0,
                priority   TEXT    NOT NULL DEFAULT 'medium',
                due_date   TEXT,
                notes_enc  TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS categories (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                name        TEXT    NOT NULL,
                color       TEXT    NOT NULL DEFAULT '#6366f1',
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, name)
            );
            CREATE TABLE IF NOT EXISTS todo_categories (
                todo_id     INTEGER NOT NULL,
                category_id INTEGER NOT NULL,
                PRIMARY KEY (todo_id, category_id),
                FOREIGN KEY (todo_id) REFERENCES todos(id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
            );
        """)
        # Migration: add theme column if missing (for existing DBs)
        cols = conn.execute("PRAGMA table_info(users)").fetchall()
        if "theme" not in [c["name"] for c in cols]:
            conn.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'light'")


# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access your tasks."
login_manager.login_message_category = "warning"


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.theme = row["theme"] if "theme" in row.keys() else "light"


@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User(row) if row else None


# ── Template filter ───────────────────────────────────────────────────────────
@app.template_filter("fmtdate")
def fmtdate(s):
    if not s:
        return ""
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%b %d, %Y")
    except ValueError:
        return s


# ── Context processors ──────────────────────────────────────────────────────────
@app.context_processor
def inject_theme():
    if current_user.is_authenticated:
        return dict(user_theme=current_user.theme)
    return dict(user_theme="light")


# ── Theme route ─────────────────────────────────────────────────────────────────
@app.route("/theme", methods=["POST"])
@login_required
def toggle_theme():
    if current_user.theme == "light":
        new_theme = "dark"
    else:
        new_theme = "light"
    with get_db() as conn:
        conn.execute("UPDATE users SET theme=? WHERE id=?", (new_theme, current_user.id))
    current_user.theme = new_theme
    return {"theme": new_theme}


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm  = request.form["confirm"]
        if not username or not email or not password:
            flash("All fields are required.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
                        (username, email, generate_password_hash(password)),
                    )
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username or email already taken.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row), remember="remember" in request.form)
            return redirect(request.args.get("next") or url_for("index"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    today = date.today().isoformat()
    with get_db() as conn:
        active = conn.execute(
            f"SELECT * FROM todos WHERE user_id=? AND done=0 ORDER BY {_PRIORITY_ORDER}, created_at",
            (current_user.id,),
        ).fetchall()
        completed = conn.execute(
            "SELECT * FROM todos WHERE user_id=? AND done=1 ORDER BY created_at DESC",
            (current_user.id,),
        ).fetchall()
        categories = conn.execute(
            "SELECT * FROM categories WHERE user_id=? ORDER BY name",
            (current_user.id,),
        ).fetchall()
        todo_cats = conn.execute("""
            SELECT tc.todo_id, c.id, c.name, c.color
            FROM todo_categories tc
            JOIN categories c ON c.id = tc.category_id
            WHERE c.user_id=?
        """, (current_user.id,)).fetchall()

    cat_map = {}
    for row in todo_cats:
        cat_map.setdefault(row["todo_id"], []).append({"id": row["id"], "name": row["name"], "color": row["color"]})

    def enrich(todos):
        return [{**dict(t), "categories": cat_map.get(t["id"], [])} for t in todos]

    overdue    = enrich([t for t in active if t["due_date"] and t["due_date"] < today])
    today_list = enrich([t for t in active if t["due_date"] == today])
    upcoming   = enrich([t for t in active if t["due_date"] and t["due_date"] > today])
    no_date    = enrich([t for t in active if not t["due_date"]])
    completed  = enrich(completed)
    active_count = len(overdue) + len(today_list) + len(upcoming) + len(no_date)
    return render_template(
        "index.html",
        overdue=overdue,
        today_list=today_list,
        upcoming=upcoming,
        no_date=no_date,
        completed=completed,
        active_count=active_count,
        today=today,
        categories=categories,
    )


# ── Task CRUD ─────────────────────────────────────────────────────────────────
@app.route("/add", methods=["POST"])
@login_required
def add():
    title    = request.form.get("title", "").strip()
    priority = request.form.get("priority", "medium")
    due_date = request.form.get("due_date", "").strip() or None
    notes    = request.form.get("notes", "").strip()
    category_ids = request.form.getlist("category_ids")
    if priority not in ("low", "medium", "high"):
        priority = "medium"
    if title:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO todos (user_id,title,priority,due_date,notes_enc) VALUES (?,?,?,?,?)",
                (current_user.id, title, priority, due_date,
                 encrypt(notes) if notes else None),
            )
            todo_id = cur.lastrowid
            for cat_id in category_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO todo_categories (todo_id, category_id) VALUES (?,?)",
                    (todo_id, cat_id),
                )
    return redirect(url_for("index"))


@app.route("/edit/<int:todo_id>", methods=["GET", "POST"])
@login_required
def edit(todo_id):
    with get_db() as conn:
        todo = conn.execute(
            "SELECT * FROM todos WHERE id=? AND user_id=?",
            (todo_id, current_user.id),
        ).fetchone()
        categories = conn.execute(
            "SELECT * FROM categories WHERE user_id=? ORDER BY name",
            (current_user.id,),
        ).fetchall()
        todo_cats = conn.execute(
            "SELECT category_id FROM todo_categories WHERE todo_id=?", (todo_id,)
        ).fetchall()
        todo_cat_ids = {row["category_id"] for row in todo_cats}
    if not todo:
        return redirect(url_for("index"))
    if request.method == "POST":
        title    = request.form.get("title", "").strip()
        priority = request.form.get("priority", "medium")
        due_date = request.form.get("due_date", "").strip() or None
        notes    = request.form.get("notes", "").strip()
        category_ids = request.form.getlist("category_ids")
        if priority not in ("low", "medium", "high"):
            priority = "medium"
        if title:
            with get_db() as conn:
                conn.execute(
                    "UPDATE todos SET title=?,priority=?,due_date=?,notes_enc=?"
                    " WHERE id=? AND user_id=?",
                    (title, priority, due_date,
                     encrypt(notes) if notes else None,
                     todo_id, current_user.id),
                )
                conn.execute("DELETE FROM todo_categories WHERE todo_id=?", (todo_id,))
                for cat_id in category_ids:
                    conn.execute(
                        "INSERT OR IGNORE INTO todo_categories (todo_id, category_id) VALUES (?,?)",
                        (todo_id, cat_id),
                    )
        return redirect(url_for("index"))
    notes_dec = decrypt(todo["notes_enc"]) if todo["notes_enc"] else ""
    return render_template("edit.html", todo=todo, notes=notes_dec, categories=categories, todo_cat_ids=todo_cat_ids)


@app.route("/toggle/<int:todo_id>", methods=["POST"])
@login_required
def toggle(todo_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE todos SET done = NOT done WHERE id=? AND user_id=?",
            (todo_id, current_user.id),
        )
    return redirect(url_for("index"))


@app.route("/delete/<int:todo_id>", methods=["POST"])
@login_required
def delete(todo_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM todos WHERE id=? AND user_id=?",
            (todo_id, current_user.id),
        )
    return redirect(url_for("index"))


@app.route("/clear-completed", methods=["POST"])
@login_required
def clear_completed():
    with get_db() as conn:
        conn.execute(
            "DELETE FROM todos WHERE user_id=? AND done=1", (current_user.id,)
        )
    return redirect(url_for("index"))


# ── Category CRUD ───────────────────────────────────────────────────────────────
@app.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        color = request.form.get("color", "#6366f1")
        if name:
            with get_db() as conn:
                try:
                    conn.execute(
                        "INSERT INTO categories (user_id, name, color) VALUES (?,?,?)",
                        (current_user.id, name, color),
                    )
                except sqlite3.IntegrityError:
                    flash("Category name already exists.", "danger")
        return redirect(url_for("categories"))
    with get_db() as conn:
        cats = conn.execute(
            "SELECT * FROM categories WHERE user_id=? ORDER BY name",
            (current_user.id,),
        ).fetchall()
    return render_template("categories.html", categories=cats)


@app.route("/categories/<int:cat_id>/delete", methods=["POST"])
@login_required
def delete_category(cat_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM categories WHERE id=? AND user_id=?", (cat_id, current_user.id)
        )
    return redirect(url_for("categories"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
