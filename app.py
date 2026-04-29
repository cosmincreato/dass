from datetime import datetime, timezone, timedelta
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

from db import get_db, close_db, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"

app.config["SESSION_COOKIE_HTTPONLY"] = False 
app.config["SESSION_COOKIE_SECURE"] = False 
app.config["SESSION_COOKIE_SAMESITE"] = None 
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=100)

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

        created_at = datetime.now(timezone.utc).isoformat()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, password, created_at),
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

        query = f"SELECT * FROM users WHERE email = '{email}'"
        print("LOGIN QUERY:", query)
        user = db.execute(query).fetchone()

        if not user:
            flash("User does not exist.")
            return render_template("login.html")

        if user["password_hash"] != password:
            flash("Incorrect password.")
            return render_template("login.html")

        if user["locked"]:
            flash("Account is locked.")
            return render_template("login.html")

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
        
        token = user["email"]
        db.execute(
            "UPDATE users SET password_reset_token = ? WHERE id = ?",
            (token, user["id"]),
        )
        db.commit()
        print(f"Token: {token}")
        
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
            "SELECT * FROM users WHERE password_reset_token = ?", (token,)
        ).fetchone()
        
        if not user:
            flash("Invalid token.")
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
    
    if request.method == "POST":
        new_password = request.form.get("password") or ""
        
        if not new_password:
            flash("Password is required.")
            return render_template("reset_password.html", token=token)
        
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password, user["id"]),
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