from datetime import datetime, timezone, timedelta
import sqlite3
import re
import bcrypt
import secrets

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

from db import get_db, close_db, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Initialized the database.")

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def login_required():
    if not session.get("user_id"):
        abort(401)

def validate_password(password):
    """
    Validate password strength.
    Returns (is_valid, error_message) tuple.
    """
    if len(password) < 8:
        return False, "Invalid password."
    
    if not re.search(r'[A-Z]', password):
        return False, "Invalid password."
    
    if not re.search(r'[a-z]', password):
        return False, "Invalid password."
    
    if not re.search(r'\d', password):
        return False, "Invalid password."
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Invalid password."
    
    return True, None

def is_login_rate_limited(email, db):
    """Check if an email is currently rate limited."""
    user = db.execute("SELECT locked, locked_until FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not user["locked"]:
        return False
    
    if user["locked_until"]:
        if datetime.fromisoformat(user["locked_until"]).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            return True
        else:
            db.execute("UPDATE users SET locked = 0, locked_until = NULL WHERE email = ?", (email,))
            db.commit()
            return False
    
    return False

def record_failed_login(email, db):
    """Record a failed login attempt and lock account if necessary."""
    user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user:
        return
    
    current_attempts = db.execute("SELECT failed_login_attempts FROM users WHERE id = ?", (user["id"],)).fetchone()
    attempts = (current_attempts["failed_login_attempts"] or 0) + 1 if current_attempts else 1
    
    if attempts >= 5:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        db.execute(
            "UPDATE users SET locked = 1, locked_until = ?, failed_login_attempts = ? WHERE id = ?",
            (locked_until.isoformat(), attempts, user["id"]),
        )
    else:
        db.execute(
            "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
            (attempts, user["id"]),
        )
    db.commit()

def reset_login_attempts(email, db):
    """Reset login attempts after successful login."""
    db.execute(
        "UPDATE users SET failed_login_attempts = 0, locked = 0, locked_until = NULL WHERE email = ?",
        (email,),
    )
    db.commit()

def generate_reset_token():
    """Generate a secure random reset token."""
    return secrets.token_urlsafe(32)

@app.get("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email and password are required.")
            return render_template("register.html")

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg)
            return render_template("register.html")

        created_at = datetime.now(timezone.utc).isoformat()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, password_hash, created_at),
            )
            db.commit()
        except sqlite3.IntegrityError as e:
            # de obicei UNIQUE constraint failed: users.email
            flash(f"Database integrity error: {e}")
            return render_template("register.html")
        except Exception as e:
            flash(f"Unexpected error: {e}")
            return render_template("register.html")

        flash("Account created. You can now log in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        db = get_db()

        if is_login_rate_limited(email, db):
            flash("Too many failed login attempts. Please try again later.")
            return render_template("login.html")

        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            record_failed_login(email, db)
            flash("Invalid email or password.")
            return render_template("login.html")

        if not bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
            record_failed_login(email, db)
            flash("Invalid email or password.")
            return render_template("login.html")

        if user["locked"]:
            flash("Account is locked.")
            return render_template("login.html")

        reset_login_attempts(email, db)
        
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        flash(f"Logged in as: {user['email']} (DEMO INSECURE)")
        return redirect(url_for("profile"))

    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not user:
            flash("A reset link has been sent.")
            return render_template("forgot_password.html")
        
        token = generate_reset_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        
        db.execute(
            "UPDATE users SET password_reset_token = ?, password_reset_token_expires_at = ?, password_reset_token_used = 0 WHERE id = ?",
            (token, expires_at, user["id"]),
        )
        db.commit()
        print(f"Reset Token: {token}")
        
        session["reset_email"] = email
        return redirect(url_for("enter_reset_token"))
    
    return render_template("forgot_password.html")

@app.route("/enter-reset-token", methods=["GET", "POST"])
def enter_reset_token():
    email = session.get("reset_email")
    
    if not email:
        flash("Session expired. Please start over.")
        return redirect(url_for("forgot_password"))
    
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        
        if not token:
            flash("Token is required.")
            return render_template("enter_reset_token.html", email=email)
        
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE password_reset_token = ? AND email = ?", (token, email)
        ).fetchone()
        
        if not user:
            flash("Invalid token.")
            return render_template("enter_reset_token.html", email=email)
        
        if user["password_reset_token_expires_at"]:
            expires_at = datetime.fromisoformat(user["password_reset_token_expires_at"]).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                flash("Token has expired.")
                return render_template("enter_reset_token.html", email=email)
        
        if user["password_reset_token_used"]:
            flash("Token has already been used.")
            return render_template("enter_reset_token.html", email=email)
        
        session["reset_token"] = token
        return redirect(url_for("reset_password", token=token))
    
    return render_template("enter_reset_token.html", email=email)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE password_reset_token = ?", (token,)
    ).fetchone()
    
    if not user:
        flash("Invalid or expired reset token.")
        return redirect(url_for("login"))
    
    if user["password_reset_token_expires_at"]:
        expires_at = datetime.fromisoformat(user["password_reset_token_expires_at"]).replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            flash("Reset token has expired.")
            return redirect(url_for("forgot_password"))
    
    if user["password_reset_token_used"]:
        flash("This reset link has already been used.")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        new_password = request.form.get("password") or ""
        
        if not new_password:
            flash("Password is required.")
            return render_template("reset_password.html", token=token)
        
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            flash(error_msg)
            return render_template("reset_password.html", token=token)
        
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.execute(
            "UPDATE users SET password_hash = ?, password_reset_token_used = 1 WHERE id = ?",
            (password_hash, user["id"]),
        )
        db.commit()
        
        flash("Password reset successfully. You can now log in.")
        return redirect(url_for("login"))
    
    return render_template("reset_password.html", token=token)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()

    if request.method == "POST":
        pass

    return render_template("profile.html", user=user)

@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    login_required()
    user = current_user()
    db = get_db()

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        severity = (request.form.get("severity") or "").strip()

        if not title or not description or not severity:
            flash("Title, description, and severity are required.")
            return render_template("tickets.html", user=user, tickets=[])

        if severity not in ["LOW", "MED", "HIGH"]:
            flash("Invalid severity.")
            return render_template("tickets.html", user=user, tickets=[])

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO tickets (title, description, severity, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (title, description, severity, user["id"], now, now),
        )
        db.commit()
        flash("Ticket created successfully.")
        return redirect(url_for("tickets"))

    rows = db.execute(
        "SELECT * FROM tickets WHERE owner_id = ? ORDER BY created_at DESC LIMIT 50",
        (user["id"],),
    ).fetchall()
    return render_template("tickets.html", user=user, tickets=rows)

@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
def ticket_detail(ticket_id):
    login_required()
    user = current_user()
    db = get_db()

    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        abort(404)

    if request.method == "POST":
        new_status = (request.form.get("status") or "").strip()
        if new_status not in ["OPEN", "IN_PROGRESS", "RESOLVED"]:
            flash("Invalid status.")
            return render_template("ticket_detail.html", ticket=ticket, user=user)

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now, ticket_id),
        )
        db.commit()
        flash("Ticket updated.")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return render_template("ticket_detail.html", ticket=ticket, user=user)