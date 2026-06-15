import gc
import os
import tempfile

import pytest

import app as app_module

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app_module.DB = db_path
    app_module.app.config["TESTING"] = True
    with app_module.app.app_context():
        app_module.init_db()
    yield app_module.app
    os.close(db_fd)
    gc.collect()  # flush any sqlite3.Connection objects held by reference cycles
    try:
        os.unlink(db_path)
    except PermissionError:
        pass  # Windows may hold the file briefly; the OS temp-cleaner will pick it up


@pytest.fixture()
def client(app):
    return app.test_client()


def _register(client, username="alice", email="alice@example.com", password="password123"):
    return client.post(
        "/register",
        data={"username": username, "email": email, "password": password, "confirm": password},
        follow_redirects=True,
    )


def _login(client, username="alice", password="password123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


@pytest.fixture()
def auth_client(client):
    _register(client)
    _login(client)
    return client


# ── Unit tests: encryption ────────────────────────────────────────────────────

class TestEncryption:
    def test_roundtrip(self, app):
        plain = "my secret note"
        assert app_module.decrypt(app_module.encrypt(plain)) == plain

    def test_ciphertext_differs_from_plaintext(self, app):
        plain = "hello"
        assert app_module.encrypt(plain) != plain

    def test_invalid_token_returns_empty_string(self, app):
        assert app_module.decrypt("not-a-valid-fernet-token") == ""

    def test_empty_token_returns_empty_string(self, app):
        assert app_module.decrypt("") == ""

    def test_encrypt_unicode(self, app):
        plain = "こんにちは"
        assert app_module.decrypt(app_module.encrypt(plain)) == plain


# ── Unit tests: fmtdate template filter ──────────────────────────────────────

class TestFmtdate:
    def test_valid_date(self, app):
        assert app_module.fmtdate("2025-12-25") == "Dec 25, 2025"

    def test_empty_string_returns_empty(self, app):
        assert app_module.fmtdate("") == ""

    def test_none_returns_empty(self, app):
        assert app_module.fmtdate(None) == ""

    def test_invalid_format_returns_original_value(self, app):
        assert app_module.fmtdate("not-a-date") == "not-a-date"

    def test_partial_date_returns_original_value(self, app):
        assert app_module.fmtdate("2025-12") == "2025-12"


# ── Auth: register ────────────────────────────────────────────────────────────

class TestRegister:
    def test_success_flashes_confirmation(self, client):
        rv = _register(client)
        assert b"Account created" in rv.data

    def test_success_redirects_to_login(self, client):
        rv = client.post(
            "/register",
            data={"username": "u", "email": "u@x.com", "password": "pass1234", "confirm": "pass1234"},
            follow_redirects=False,
        )
        assert rv.status_code == 302
        assert rv.location.endswith("/login")

    def test_duplicate_username_rejected(self, client):
        _register(client)
        rv = _register(client)  # same username + email
        assert b"already taken" in rv.data

    def test_duplicate_email_rejected(self, client):
        _register(client)
        rv = _register(client, username="alice2", email="alice@example.com")
        assert b"already taken" in rv.data

    def test_password_mismatch_rejected(self, client):
        rv = client.post(
            "/register",
            data={"username": "u", "email": "u@x.com", "password": "pass1234", "confirm": "different"},
            follow_redirects=True,
        )
        assert b"do not match" in rv.data

    def test_password_too_short_rejected(self, client):
        rv = client.post(
            "/register",
            data={"username": "u", "email": "u@x.com", "password": "short", "confirm": "short"},
            follow_redirects=True,
        )
        assert b"at least 8" in rv.data

    def test_empty_fields_rejected(self, client):
        rv = client.post(
            "/register",
            data={"username": "", "email": "", "password": "", "confirm": ""},
            follow_redirects=True,
        )
        assert b"required" in rv.data

    def test_already_authenticated_redirects_away(self, auth_client):
        rv = auth_client.get("/register", follow_redirects=False)
        assert rv.status_code == 302


# ── Auth: login ───────────────────────────────────────────────────────────────

class TestLogin:
    def test_valid_credentials_log_in(self, client):
        _register(client)
        rv = _login(client)
        assert rv.status_code == 200

    def test_wrong_password_rejected(self, client):
        _register(client)
        rv = client.post(
            "/login",
            data={"username": "alice", "password": "wrongpass"},
            follow_redirects=True,
        )
        assert b"Invalid username or password" in rv.data

    def test_unknown_user_rejected(self, client):
        rv = client.post(
            "/login",
            data={"username": "nobody", "password": "password123"},
            follow_redirects=True,
        )
        assert b"Invalid username or password" in rv.data

    def test_already_authenticated_redirects_away(self, auth_client):
        rv = auth_client.get("/login", follow_redirects=False)
        assert rv.status_code == 302


# ── Auth: logout ──────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_redirects_to_login(self, auth_client):
        rv = auth_client.get("/logout", follow_redirects=False)
        assert rv.status_code == 302
        assert "login" in rv.location

    def test_logout_unauthenticated_redirects_to_login(self, client):
        rv = client.get("/logout", follow_redirects=False)
        assert rv.status_code == 302
        assert "login" in rv.location


# ── Security: all protected routes require login ──────────────────────────────

class TestProtectedRoutes:
    GET_ROUTES = ["/", "/edit/1"]
    POST_ROUTES = ["/add", "/toggle/1", "/delete/1", "/clear-completed"]

    def test_unauthenticated_get_redirects_to_login(self, client):
        for route in self.GET_ROUTES:
            rv = client.get(route, follow_redirects=False)
            assert rv.status_code == 302, f"Expected redirect on GET {route}"
            assert "login" in rv.location, f"Expected login redirect on GET {route}"

    def test_unauthenticated_post_redirects_to_login(self, client):
        for route in self.POST_ROUTES:
            rv = client.post(route, follow_redirects=False)
            assert rv.status_code == 302, f"Expected redirect on POST {route}"
            assert "login" in rv.location, f"Expected login redirect on POST {route}"


# ── CRUD: add ─────────────────────────────────────────────────────────────────

class TestAddTodo:
    def test_add_todo_appears_on_dashboard(self, auth_client):
        rv = auth_client.post(
            "/add",
            data={"title": "Buy groceries", "priority": "high", "due_date": "", "notes": ""},
            follow_redirects=True,
        )
        assert b"Buy groceries" in rv.data

    def test_notes_stored_encrypted_not_plaintext(self, auth_client):
        auth_client.post(
            "/add",
            data={"title": "Secret", "priority": "medium", "notes": "private note"},
        )
        with app_module.get_db() as conn:
            row = conn.execute("SELECT notes_enc FROM todos WHERE title='Secret'").fetchone()
        assert row is not None
        assert row["notes_enc"] != "private note"
        assert app_module.decrypt(row["notes_enc"]) == "private note"

    def test_empty_title_is_not_saved(self, auth_client):
        auth_client.post("/add", data={"title": "  ", "priority": "high"})
        with app_module.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM todos").fetchone()[0]
        assert count == 0

    def test_invalid_priority_defaults_to_medium(self, auth_client):
        auth_client.post("/add", data={"title": "Task", "priority": "ultra"})
        with app_module.get_db() as conn:
            row = conn.execute("SELECT priority FROM todos WHERE title='Task'").fetchone()
        assert row["priority"] == "medium"

    def test_blank_due_date_stored_as_null(self, auth_client):
        auth_client.post("/add", data={"title": "Undated", "priority": "low", "due_date": ""})
        with app_module.get_db() as conn:
            row = conn.execute("SELECT due_date FROM todos WHERE title='Undated'").fetchone()
        assert row["due_date"] is None

    def test_all_valid_priorities_accepted(self, auth_client):
        for priority in ("low", "medium", "high"):
            auth_client.post("/add", data={"title": f"Task {priority}", "priority": priority})
        with app_module.get_db() as conn:
            rows = conn.execute("SELECT priority FROM todos").fetchall()
        priorities = {r["priority"] for r in rows}
        assert priorities == {"low", "medium", "high"}


# ── CRUD: edit ────────────────────────────────────────────────────────────────

class TestEditTodo:
    def _add_and_get_id(self, auth_client, title="Original"):
        auth_client.post("/add", data={"title": title, "priority": "low"})
        with app_module.get_db() as conn:
            return conn.execute("SELECT id FROM todos WHERE title=?", (title,)).fetchone()["id"]

    def test_edit_get_shows_existing_values(self, auth_client):
        todo_id = self._add_and_get_id(auth_client, "My task")
        rv = auth_client.get(f"/edit/{todo_id}")
        assert rv.status_code == 200
        assert b"My task" in rv.data

    def test_edit_post_updates_title(self, auth_client):
        todo_id = self._add_and_get_id(auth_client)
        auth_client.post(
            f"/edit/{todo_id}",
            data={"title": "Updated", "priority": "high", "due_date": "", "notes": ""},
            follow_redirects=True,
        )
        with app_module.get_db() as conn:
            row = conn.execute("SELECT title FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["title"] == "Updated"

    def test_edit_decrypts_notes_in_form(self, auth_client):
        auth_client.post("/add", data={"title": "T", "priority": "low", "notes": "secret"})
        with app_module.get_db() as conn:
            todo_id = conn.execute("SELECT id FROM todos").fetchone()["id"]
        rv = auth_client.get(f"/edit/{todo_id}")
        assert b"secret" in rv.data

    def test_edit_nonexistent_todo_redirects(self, auth_client):
        rv = auth_client.get("/edit/9999", follow_redirects=False)
        assert rv.status_code == 302

    def test_edit_empty_title_is_ignored(self, auth_client):
        todo_id = self._add_and_get_id(auth_client, "Keep this")
        auth_client.post(
            f"/edit/{todo_id}",
            data={"title": "", "priority": "high", "due_date": "", "notes": ""},
        )
        with app_module.get_db() as conn:
            row = conn.execute("SELECT title FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["title"] == "Keep this"


# ── CRUD: toggle ──────────────────────────────────────────────────────────────

class TestToggleTodo:
    def _add_and_get_id(self, auth_client):
        auth_client.post("/add", data={"title": "Toggle me", "priority": "medium"})
        with app_module.get_db() as conn:
            return conn.execute("SELECT id FROM todos").fetchone()["id"]

    def test_toggle_marks_as_done(self, auth_client):
        todo_id = self._add_and_get_id(auth_client)
        auth_client.post(f"/toggle/{todo_id}")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT done FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["done"] == 1

    def test_toggle_twice_returns_to_active(self, auth_client):
        todo_id = self._add_and_get_id(auth_client)
        auth_client.post(f"/toggle/{todo_id}")
        auth_client.post(f"/toggle/{todo_id}")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT done FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["done"] == 0


# ── CRUD: delete ──────────────────────────────────────────────────────────────

class TestDeleteTodo:
    def test_delete_removes_todo(self, auth_client):
        auth_client.post("/add", data={"title": "Delete me", "priority": "low"})
        with app_module.get_db() as conn:
            todo_id = conn.execute("SELECT id FROM todos").fetchone()["id"]
        auth_client.post(f"/delete/{todo_id}")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT * FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row is None

    def test_delete_nonexistent_todo_is_silent(self, auth_client):
        rv = auth_client.post("/delete/9999", follow_redirects=True)
        assert rv.status_code == 200


# ── CRUD: clear completed ─────────────────────────────────────────────────────

class TestClearCompleted:
    def test_removes_done_tasks_keeps_active(self, auth_client):
        auth_client.post("/add", data={"title": "Done task", "priority": "low"})
        auth_client.post("/add", data={"title": "Active task", "priority": "low"})
        with app_module.get_db() as conn:
            done_id = conn.execute("SELECT id FROM todos WHERE title='Done task'").fetchone()["id"]
        auth_client.post(f"/toggle/{done_id}")
        auth_client.post("/clear-completed")
        with app_module.get_db() as conn:
            titles = [r["title"] for r in conn.execute("SELECT title FROM todos").fetchall()]
        assert "Active task" in titles
        assert "Done task" not in titles

    def test_clear_with_no_completed_is_safe(self, auth_client):
        auth_client.post("/add", data={"title": "Active", "priority": "low"})
        rv = auth_client.post("/clear-completed", follow_redirects=True)
        assert rv.status_code == 200
        with app_module.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM todos").fetchone()[0]
        assert count == 1


# ── Security: user isolation (IDOR prevention) ────────────────────────────────

class TestUserIsolation:
    """Verify User B cannot read, modify, or delete User A's data."""

    def _setup(self, client):
        """Register Alice, add a task, log out. Register Bob, log in. Return Alice's todo id."""
        _register(client, username="alice", email="alice@example.com")
        _login(client, username="alice")
        client.post("/add", data={"title": "Alice private task", "priority": "high"})
        with app_module.get_db() as conn:
            todo_id = conn.execute("SELECT id FROM todos").fetchone()["id"]
        client.get("/logout")
        _register(client, username="bob", email="bob@example.com")
        _login(client, username="bob")
        return todo_id

    def test_bob_dashboard_does_not_show_alices_task(self, client):
        self._setup(client)
        rv = client.get("/")
        assert b"Alice private task" not in rv.data

    def test_bob_cannot_edit_alices_todo(self, client):
        todo_id = self._setup(client)
        client.post(
            f"/edit/{todo_id}",
            data={"title": "Hacked by Bob", "priority": "low", "due_date": "", "notes": ""},
        )
        with app_module.get_db() as conn:
            row = conn.execute("SELECT title FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["title"] == "Alice private task"

    def test_bob_cannot_delete_alices_todo(self, client):
        todo_id = self._setup(client)
        client.post(f"/delete/{todo_id}")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT * FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row is not None

    def test_bob_cannot_toggle_alices_todo(self, client):
        todo_id = self._setup(client)
        client.post(f"/toggle/{todo_id}")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT done FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row["done"] == 0

    def test_bob_cannot_view_edit_page_for_alices_todo(self, client):
        todo_id = self._setup(client)
        rv = client.get(f"/edit/{todo_id}", follow_redirects=False)
        # Redirects to index because the WHERE id=? AND user_id=? returns no row
        assert rv.status_code == 302

    def test_clear_completed_does_not_touch_other_users_todos(self, client):
        todo_id = self._setup(client)
        # Mark Alice's task done directly
        with app_module.get_db() as conn:
            conn.execute("UPDATE todos SET done=1 WHERE id=?", (todo_id,))
        # Bob clears his completed tasks — Alice's task must survive
        client.post("/clear-completed")
        with app_module.get_db() as conn:
            row = conn.execute("SELECT * FROM todos WHERE id=?", (todo_id,)).fetchone()
        assert row is not None


# ── Theme toggle ────────────────────────────────────────────────────────────────

class TestThemeToggle:
    def test_default_theme_is_light(self, auth_client):
        with app_module.get_db() as conn:
            theme = conn.execute(
                "SELECT theme FROM users WHERE username='alice'"
            ).fetchone()["theme"]
        assert theme == "light"

    def test_toggle_changes_to_dark(self, auth_client):
        rv = auth_client.post("/theme")
        assert rv.status_code == 200
        assert rv.json == {"theme": "dark"}
        with app_module.get_db() as conn:
            theme = conn.execute(
                "SELECT theme FROM users WHERE username='alice'"
            ).fetchone()["theme"]
        assert theme == "dark"

    def test_toggle_twice_returns_to_light(self, auth_client):
        auth_client.post("/theme")
        auth_client.post("/theme")
        with app_module.get_db() as conn:
            theme = conn.execute(
                "SELECT theme FROM users WHERE username='alice'"
            ).fetchone()["theme"]
        assert theme == "light"

    def test_unauthenticated_redirects(self, client):
        rv = client.post("/theme", follow_redirects=False)
        assert rv.status_code == 302
        assert "login" in rv.location

    def test_theme_persists_across_requests(self, auth_client):
        auth_client.post("/theme")
        rv = auth_client.get("/")
        assert b'data-theme="dark"' in rv.data or b"dark" in rv.data


# ── Categories ──────────────────────────────────────────────────────────────────

class TestCategories:
    def _add_category(self, auth_client, name="Work", color="#dc3545"):
        return auth_client.post(
            "/categories",
            data={"name": name, "color": color},
            follow_redirects=True,
        )

    def test_add_category_shows_in_list(self, auth_client):
        rv = self._add_category(auth_client)
        assert b"Work" in rv.data

    def test_duplicate_category_name_rejected(self, auth_client):
        self._add_category(auth_client, name="Work")
        rv = self._add_category(auth_client, name="Work")
        assert b"already exists" in rv.data

    def test_category_color_is_stored(self, auth_client):
        self._add_category(auth_client, name="Personal", color="#10b981")
        with app_module.get_db() as conn:
            row = conn.execute(
                "SELECT color FROM categories WHERE name='Personal'"
            ).fetchone()
        assert row["color"] == "#10b981"

    def test_categories_are_user_scoped(self, client):
        _register(client, username="alice", email="alice@example.com")
        _login(client, username="alice")
        self._add_category(client, name="AliceCat")
        client.get("/logout")
        rv = _register(client, username="bob", email="bob@example.com")
        if b"already taken" in rv.data or rv.status_code == 302:
            pass
        _login(client, username="bob")
        rv = client.get("/categories")
        assert b"AliceCat" not in rv.data

    def test_delete_category(self, auth_client):
        self._add_category(auth_client, name="Temp")
        with app_module.get_db() as conn:
            cat_id = conn.execute(
                "SELECT id FROM categories WHERE name='Temp'"
            ).fetchone()["id"]
        auth_client.post(f"/categories/{cat_id}/delete")
        with app_module.get_db() as conn:
            row = conn.execute(
                "SELECT id FROM categories WHERE id=?", (cat_id,)
            ).fetchone()
        assert row is None

    def test_category_badges_appear_on_dashboard(self, auth_client):
        self._add_category(auth_client, name="Urgent", color="#dc3545")
        with app_module.get_db() as conn:
            cat_id = conn.execute(
                "SELECT id FROM categories WHERE name='Urgent'"
            ).fetchone()["id"]
        auth_client.post(
            "/add",
            data={"title": "Important task", "priority": "high",
                  "due_date": "", "notes": "", "category_ids": [str(cat_id)]},
            follow_redirects=True,
        )
        rv = auth_client.get("/")
        assert b"Urgent" in rv.data

    def test_category_persists_on_edit(self, auth_client):
        self._add_category(auth_client, name="Work")
        with app_module.get_db() as conn:
            cat_id = conn.execute(
                "SELECT id FROM categories WHERE name='Work'"
            ).fetchone()["id"]
        auth_client.post(
            "/add",
            data={"title": "Task", "priority": "low",
                  "due_date": "", "notes": "", "category_ids": [str(cat_id)]},
        )
        with app_module.get_db() as conn:
            todo_id = conn.execute("SELECT id FROM todos").fetchone()["id"]
        rv = auth_client.get(f"/edit/{todo_id}")
        assert b"Work" in rv.data
