import os
import sqlite3
from datetime import timedelta
from hashlib import md5
from dotenv import load_dotenv
from flask import Flask, render_template, session, request, redirect, url_for, flash, abort
from db import get_db, close_db, init_db

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default-key")
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Baza de date a fost initializata.")

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
            flash("Email-ul si parola sunt obligatorii.")
            return render_template("register.html")

        password_hash = md5(password.encode()).hexdigest()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, password_hash, "USER"),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Email-ul este deja folosit.")
            return render_template("register.html")
        except Exception as e:
            flash(f"Eroare neasteptata {e}")
            return render_template("register.html")

        flash("Cont creat cu success.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        db = get_db()

        user_email = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user_email:
            flash("Email inexistent.")
            return render_template("login.html")

        user = db.execute(
            "SELECT * FROM users WHERE email = ? AND password_hash = ?",
            (email, md5(password.encode()).hexdigest()),
        ).fetchone()

        if not user:
            flash("Parola invalida.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("home"))

    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()
    return render_template("profile.html", user=user)

@app.post("/generate-reset-token")
def generate_reset_token():
    email = (request.form.get("email") or "").strip()

    if not email:
        flash("Introdu adresa de email.")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        flash("Dacă email-ul există, vei primi instrucțiuni de resetare.")
        return redirect(url_for("login"))

    token = md5(email.encode()).hexdigest()

    db.execute(
        "UPDATE users SET password_reset_token = ? WHERE id = ?",
        (token, user["id"])
    )
    db.commit()

    reset_link = url_for("reset_password", token=token, _external=True)
    flash(f"Link resetare: {reset_link}")

    return redirect(url_for("login"))

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE password_reset_token = ?",
        (token,)
    ).fetchone()

    if not user:
        flash("Token invalid.")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password") or ""

        if not password:
            flash("Câmpul este obligatoriu.")
            return render_template("reset_password.html", token=token)

        password_hash = md5(password.encode()).hexdigest()
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user["id"])
        )
        db.commit()

        flash("Parola a fost resetată cu succes.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)
