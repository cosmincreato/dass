from datetime import datetime, timezone
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, close_db, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"

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
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username și parola sunt obligatorii.")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            db.commit()
        except sqlite3.IntegrityError as e:
            # de obicei UNIQUE constraint failed: users.username
            flash(f"Eroare integritate DB: {e}")
            return render_template("register.html")
        except Exception as e:
            flash(f"Eroare neașteptată: {e}")
            return render_template("register.html")

        flash("Cont creat. Te poți autentifica.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        db = get_db()

        query = f"SELECT * FROM users WHERE username = '{username}'"
        print("LOGIN QUERY:", query)
        user = db.execute(query).fetchone()

        if not user:
            flash("Credențiale invalide.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        flash(f"Logat ca: {user['username']} (DEMO INSECURE)")
        return redirect(url_for("profile"))

    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()

    if request.method == "POST":
        bio = request.form.get("bio") or ""
        db = get_db()
        db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
        db.commit()
        flash("Bio actualizat.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    login_required()
    user = current_user()
    db = get_db()

    if request.method == "POST":
        to_username = (request.form.get("to_username") or "").strip()
        amount_raw = (request.form.get("amount") or "").strip()

        try:
            amount = int(amount_raw)
        except ValueError:
            flash("Suma trebuie să fie un număr întreg.")
            return render_template("transfer.html", user=user)

        if amount <= 0:
            flash("Suma trebuie să fie > 0.")
            return render_template("transfer.html", user=user)

        to_user = db.execute("SELECT * FROM users WHERE username = ?", (to_username,)).fetchone()
        if not to_user:
            flash("Destinatar inexistent.")
            return render_template("transfer.html", user=user)

        if to_user["id"] == user["id"]:
            flash("Nu poți transfera către tine.")
            return render_template("transfer.html", user=user)

        # refresh balance
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if user["balance"] < amount:
            flash("Fonduri insuficiente.")
            return render_template("transfer.html", user=user)

        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user["id"]))
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_user["id"]))
        db.execute(
            "INSERT INTO transfers (from_user_id, to_user_id, amount, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], to_user["id"], amount, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        flash(f"Transfer efectuat către {to_username}: {amount}.")
        return redirect(url_for("profile"))

    return render_template("transfer.html", user=user)

@app.get("/history")
def history():
    login_required()
    user = current_user()
    db = get_db()
    rows = db.execute(
        """
        SELECT t.amount, t.created_at, u_from.username AS from_user, u_to.username AS to_user
        FROM transfers t
        JOIN users u_from ON u_from.id = t.from_user_id
        JOIN users u_to ON u_to.id = t.to_user_id
        WHERE t.from_user_id = ? OR t.to_user_id = ?
        ORDER BY t.id DESC
        LIMIT 20
        """,
        (user["id"], user["id"]),
    ).fetchall()
    return render_template("base.html", content=rows)