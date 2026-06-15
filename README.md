# TaskFlow

A full-featured to-do list web application built with Flask. TaskFlow supports user authentication, task prioritization, due dates, and Fernet-encrypted private notes — all in a clean Bootstrap 5 dashboard.

## Features

- **User Auth** — Register and log in with hashed passwords (Werkzeug `pbkdf2:sha256`). Sessions persist with "Remember me." Every user's data is fully isolated.
- **Task CRUD** — Create, edit, toggle done, and delete tasks. Title, priority (Low / Medium / High), and due date on every task.
- **Dashboard** — Active tasks automatically sectioned into **Overdue**, **Today**, **Upcoming**, and **No Due Date**, with stat cards at the top.
- **Encrypted Private Notes** — Per-task notes encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before storage. A lock icon shows a note exists without revealing its contents. Notes are only decrypted when you open the edit page.
- **Persistent Secrets** — Flask secret key and Fernet key are generated once on first run and stored in `secrets.json`. Sessions and encrypted notes survive server restarts.
- **Priority Sorting** — Tasks sorted High → Medium → Low within each section.
- **Clear Completed** — One-click bulk delete of all completed tasks.

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Flask 3.x |
| Auth | Flask-Login + Werkzeug |
| Encryption | cryptography (Fernet) |
| Database | SQLite (stdlib `sqlite3`) |
| Templating | Jinja2 |
| UI | Bootstrap 5.3 + Bootstrap Icons 1.11 |

## Installation

### Prerequisites

- Python 3.9+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/hananmd/TaskFlow.git
cd taskflow

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Open your browser at `http://127.0.0.1:5000`.

On first run, `secrets.json` and `todos.db` are created automatically — no manual setup needed.

## Usage

1. Go to `/register` and create an account.
2. Log in at `/login`.
3. Add tasks using the form at the top of the dashboard. Set a priority and an optional due date.
4. Optionally add a private note — it will be encrypted before saving.
5. Click the circle icon to mark a task done. Click the pencil to edit it.
6. The dashboard sections (**Overdue**, **Today**, **Upcoming**, **No Due Date**) update automatically based on due dates.

## Security Notes

- Passwords are never stored in plaintext. Werkzeug hashes them with PBKDF2-SHA256 + a random salt.
- Private notes are encrypted with Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) using a key stored in `secrets.json`.
- `secrets.json` is excluded from version control. **Do not commit it.** Anyone with this file can decrypt your notes database.
- All task queries are scoped to the authenticated user — users cannot access each other's data.

## Project Structure

```
taskflow/
├── app.py              # Flask app, routes, DB, encryption
├── requirements.txt    # Python dependencies
├── secrets.json        # Auto-generated — NOT committed
├── todos.db            # SQLite database — NOT committed
└── templates/
    ├── base.html       # Navbar, flash messages, shared CSS
    ├── index.html      # Dashboard
    ├── login.html      # Login page
    ├── register.html   # Register page
    └── edit.html       # Edit task page
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**M.Y Hanan Mohamed** ([@hananmd](https://github.com/hananmd))
