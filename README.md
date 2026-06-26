Secure Login System

A web app built with Flask that demonstrates the core building blocks of secure user authentication: hashed passwords, input validation, protection from SQL injection, and session-based login/logout.

What it does

This is a small, fully working login system. Users can:


Register a new account with a username and password
Log in with their credentials
Log out, which ends their session


Behind the scenes, it follows several real security practices:

1. Hashed passwords (bcrypt)

Passwords are never stored as plain text. When a user registers, their password is hashed using bcrypt, which automatically generates a random "salt" and folds it into the hash. This means:


Even if the database were leaked, attackers would not see anyone's actual password.
Two users with the same password get completely different stored hashes.


On login, bcrypt re-hashes the entered password using the same salt and compares the result — the plain-text password is never stored or directly compared.

2. Input validation


Usernames must be 3–20 characters and contain only letters, numbers, or underscores.
Passwords must be at least 8 characters long.


This blocks malformed or suspicious input before it ever reaches the database.

3. Protection from SQL injection

All database queries use parameterized queries (the ? placeholder in SQLite), instead of building SQL strings by hand with user input. This means user input is always treated strictly as data, never as part of the SQL command itself — so an input like admin'; DROP TABLE users; -- can't be used to manipulate the database.

4. Session management


On successful login, Flask stores a signed session cookie identifying the logged-in user.
The home page checks for this session and redirects to the login page if it's missing.
Logging out clears the session completely.


Project structure

secure-login-system/
├── app.py                 # Main Flask application (routes, logic, security)
├── requirements.txt       # Python dependencies
├── .gitignore              # Keeps the database file out of version control
└── templates/
    ├── base.html          # Shared page layout and styling
    ├── login.html
    ├── register.html
    └── dashboard.html      # Shown only when logged in

How to run it


Make sure Python 3 is installed.
Clone or download this repository.
Open a terminal in the project folder and install dependencies:


   pip install -r requirements.txt


Run the app:


   python3 app.py


Open your browser to:


   http://127.0.0.1:5000

The first time it runs, it will automatically create a users.db SQLite database file to store registered users.

Try it out


Go to the registration page and create an account.
Log in with that username and password.
You'll land on a dashboard that only loads if your session is valid.
Click "Log Out" — you'll be returned to the login page, and the dashboard will no longer be accessible until you log in again.


Notes on this implementation


This project focuses on the core requirements: hashed passwords, input validation, SQL injection protection, and session management with logout. Two-Factor Authentication (2FA) was left as a possible future addition rather than implemented here, to keep the codebase small and easy to follow.
The app.secret_key in app.py is hardcoded for simplicity, since this is a learning project. In a real production app, this should be a random value stored in an environment variable, not committed to source control.


Why this matters

Weak or improperly stored passwords are one of the most common causes of account compromise. This project demonstrates the baseline practices that meaningfully reduce that risk: never storing plain-text passwords, validating input before it reaches the database, using parameterized queries to prevent injection attacks, and managing sessions so that access is only granted to authenticated users.

Possible future improvements


Add Two-Factor Authentication (2FA), e.g. via email or an authenticator app
Add password strength requirements or integrate a password strength checker
Add account lockout after repeated failed login attempts
Move the secret key and other configuration into environment variables
