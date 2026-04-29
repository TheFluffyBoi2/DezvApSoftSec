import os
import sqlite3
import bcrypt
import re
import secrets
from datetime import timedelta, datetime, timedelta
from hashlib import md5
from dotenv import load_dotenv
from flask import Flask, render_template, session, request, redirect, url_for, flash, abort
from db import get_db, close_db, init_db

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

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

def verify_password(password):
    if len(password) < 8:
        return False, "Parola trebuie să aibe un minim de 8 caractere."
    if not re.search(r"[A-Z]", password):
        return False, "Parola trebuie să conțină cel puțin o literă mare (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Parola trebuie să conțină cel puțin o literă mică (a-z)."
    if not re.search(r"\d", password):
        return False, "Parola trebuie să conțină cel puțin o cifră (0-9)."
    if not re.search(r"[!?@#$%^&*]", password):
        return False, "Parola trebuie să conțină cel puțin un caracter special (!?@#$%^&*)."
    return True, ""

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email-ul si parola sunt obligatorii.")
            return render_template("register.html")

        is_valid, error = verify_password(password)
        if not is_valid:
            flash(error)
            return render_template("register.html")

        bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(bytes, salt)

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
        now = datetime.now()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user:
            if user["locked"]:
                if user["unlocked_at"]:
                    unlock_time = datetime.fromisoformat(user["unlocked_at"])
                    if now < unlock_time:
                        time_remaining = int((unlock_time - now).total_seconds() / 60)
                        flash("Contul este blocat.")
                        return render_template("login.html")
                    else:
                        db.execute("UPDATE users SET locked = 0, failed_attempts = 0, unlocked_at = NULL WHERE id = ?",
                                   (user["id"],))
                        db.commit()
            if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
                db.commit()

                session.clear()
                session["user_id"] = user["id"]
                return redirect(url_for("home"))
            else:
                new_failed_attempts = user["failed_attempts"] + 1
                if new_failed_attempts >= 5:
                    new_unlock_time = (now + timedelta(minutes=30)).isoformat()
                    db.execute("UPDATE users SET failed_attempts = ?, locked = 1, unlocked_at = ? WHERE id = ?",
                               (new_failed_attempts, new_unlock_time, user["id"]))
                else:
                    db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?",
                               (new_failed_attempts, user["id"]))
                db.commit()

        else:
            flash("Date de autentificare invalide.")
            return render_template("login.html")

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

    token = secrets.token_urlsafe(32)

    token_expire_at = (datetime.now() + timedelta(minutes=1)).isoformat()

    db.execute(
        "UPDATE users SET password_reset_token = ?, token_expire_at = ? WHERE id = ?",
        (token, token_expire_at, user["id"])
    )
    db.commit()

    reset_link = url_for("reset_password", token=token, _external=True)
    flash("Dacă email-ul există, vei primi instrucțiuni de resetare.")
    flash(f"Link resetare: {reset_link}")

    return redirect(url_for("login"))

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    now = datetime.now()

    user = db.execute(
        "SELECT * FROM users WHERE password_reset_token = ? AND token_expire_at > ?",
        (token, now)
    ).fetchone()

    if not user:
        flash("Token invalid sau expirat.")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password") or ""

        is_valid, error = verify_password(password)

        if not is_valid:
            flash(error)
            return render_template("reset_password.html", token=token)

        bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(bytes, salt)

        db.execute(
            "UPDATE users SET password_hash = ?, password_reset_token = NULL, token_expire_at = NULL WHERE id = ?",
            (password_hash, user["id"])
        )
        db.commit()

        flash("Parola a fost resetată cu succes.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)
