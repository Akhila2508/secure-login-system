"""
Secure Login System
--------------------
A small Flask web app demonstrating the core building blocks of secure
authentication:

1. User registration and login with bcrypt-hashed passwords
   (we never store plain-text passwords anywhere)
2. Basic input validation
3. Protection from SQL injection (using parameterized queries)
4. Session management with a logout feature

This is intentionally kept small and well-commented so each security
concept is easy to find and explain.
"""

import sqlite3
import re
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)

# secret_key is required for Flask to securely sign session cookies.
# In a real production app this should come from an environment variable,
# not be hardcoded - we keep it simple here since this is a learning project.
app.secret_key = "replace-this-with-a-random-secret-key"

DB_NAME = "users.db"


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the users table if it doesn't already exist."""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def is_valid_username(username):
    """
    Only allow letters, numbers, and underscores, between 3 and 20 characters.
    This blocks weird input early, before it ever reaches the database.
    """
    return bool(re.match(r"^[A-Za-z0-9_]{3,20}$", username))


def is_valid_password(password):
    """
    Require a reasonable minimum length.
    (You could plug in the password strength checker from an earlier
    project here for a stronger check!)
    """
    return len(password) >= 8


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    if "username" in session:
        return render_template("dashboard.html", username=session["username"])
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # --- Input validation ---
        if not is_valid_username(username):
            flash("Username must be 3-20 characters and contain only letters, numbers, or underscores.")
            return render_template("register.html")

        if not is_valid_password(password):
            flash("Password must be at least 8 characters long.")
            return render_template("register.html")

        conn = get_db_connection()

        # --- SQL injection protection ---
        # We use a parameterized query (the "?" placeholder) instead of
        # building the SQL string by hand with the username. This means
        # the database treats the username strictly as data, never as
        # part of the SQL command itself - so something like
        #   admin'; DROP TABLE users; --
        # is stored harmlessly as a (rejected, due to validation above)
        # piece of text, not executed as a command.
        existing_user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing_user:
            conn.close()
            flash("That username is already taken.")
            return render_template("register.html")

        # --- Password hashing ---
        # We NEVER store the plain-text password. bcrypt generates a unique
        # random "salt" automatically and folds it into the hash, so even
        # two users with the same password get completely different hashes.
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash.decode("utf-8")),
        )
        conn.commit()
        conn.close()

        flash("Account created successfully! You can now log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        # Parameterized query again - safe from SQL injection.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user is None:
            flash("Invalid username or password.")
            return render_template("login.html")

        stored_hash = user["password_hash"].encode("utf-8")

        # bcrypt.checkpw re-hashes the entered password with the same salt
        # that's embedded in the stored hash, then compares the results.
        # The plain-text password is never stored or compared directly.
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            # --- Session management ---
            # On successful login, Flask creates a signed session cookie
            # so the server can recognize this browser on future requests
            # without asking for the password again.
            session["username"] = username
            flash("Logged in successfully.")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    # --- Logout / session management ---
    # Clearing the session removes the cookie's contents server-side,
    # so the browser is no longer recognized as logged in.
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
