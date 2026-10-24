"""
Film Creator — Flask application
A cinematic story-writing platform with auth, SQLite storage, and AI assistance.
"""

from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DATABASE_PATH = INSTANCE_DIR / "filmcreator.db"

app = Flask(__name__, instance_path=str(INSTANCE_DIR))
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = None

csrf = CSRFProtect(app)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_FIELD_LEN = 50000
MAX_TITLE_LEN = 200
MAX_GENRE_LEN = 80
MAX_PROMPT_LEN = 4000

VALID_GENRES = [
    "Action",
    "Adventure",
    "Comedy",
    "Drama",
    "Fantasy",
    "Horror",
    "Mystery",
    "Romance",
    "Sci-Fi",
    "Thriller",
    "Other",
]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DATABASE_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            genre TEXT NOT NULL DEFAULT 'Other',
            characters TEXT NOT NULL DEFAULT '',
            scenes TEXT NOT NULL DEFAULT '',
            dialogues TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_stories_user_id ON stories(user_id);
        """
    )
    db.commit()
    _bootstrap_admin(db)
    db.close()


def _bootstrap_admin(db: sqlite3.Connection) -> None:
    """Create an admin only when env vars are set and no admin exists yet."""
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    email = (os.environ.get("ADMIN_EMAIL") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""

    if not (username and email and password):
        return

    existing = db.execute(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    ).fetchone()
    if existing:
        return

    if not USERNAME_RE.match(username) or not EMAIL_RE.match(email) or len(password) < 8:
        app.logger.warning(
            "ADMIN_* env vars are set but invalid; skipping admin bootstrap."
        )
        return

    try:
        db.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
            """,
            (
                username,
                email.lower(),
                generate_password_hash(password),
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        db.commit()
        app.logger.info("Admin user '%s' created from environment variables.", username)
    except sqlite3.IntegrityError:
        app.logger.warning("Admin bootstrap skipped: username or email already exists.")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        if user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "csrf_token": generate_csrf,
        "genres": VALID_GENRES,
        "ai_configured": bool(os.environ.get("OPENAI_API_KEY")),
    }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def clean_text(value: str | None, max_len: int) -> str:
    text = (value or "").strip()
    if len(text) > max_len:
        text = text[:max_len]
    return text


def validate_registration(username: str, email: str, password: str, confirm: str):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append(
            "Username must be 3–30 characters and use only letters, numbers, and underscores."
        )
    if not EMAIL_RE.match(email) or len(email) > 120:
        errors.append("Please enter a valid email address.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if len(password) > 128:
        errors.append("Password is too long.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


def get_owned_story(story_id: int, user_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT * FROM stories WHERE id = ? AND user_id = ?",
        (story_id, user_id),
    ).fetchone()


def story_to_text(story: sqlite3.Row) -> str:
    lines = [
        f"Title: {story['title']}",
        f"Genre: {story['genre']}",
        f"Created: {story['created_at']}",
        f"Updated: {story['updated_at']}",
        "",
        "=" * 40,
        "CHARACTERS",
        "=" * 40,
        story["characters"] or "(none)",
        "",
        "=" * 40,
        "SCENES",
        "=" * 40,
        story["scenes"] or "(none)",
        "",
        "=" * 40,
        "DIALOGUES",
        "=" * 40,
        story["dialogues"] or "(none)",
        "",
        "— Exported from Film Creator —",
    ]
    return "\n".join(lines)


def story_to_pdf(story: sqlite3.Row) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=inch,
        rightMargin=inch,
        topMargin=inch,
        bottomMargin=inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "StoryTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "SectionHead",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
    )

    def esc(text: str) -> str:
        return (
            (text or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
        )

    story_flow = [
        Paragraph(esc(story["title"]), title_style),
        Paragraph(f"Genre: {esc(story['genre'])}", body_style),
        Spacer(1, 8),
        Paragraph("Characters", heading_style),
        Paragraph(esc(story["characters"] or "(none)"), body_style),
        Paragraph("Scenes", heading_style),
        Paragraph(esc(story["scenes"] or "(none)"), body_style),
        Paragraph("Dialogues", heading_style),
        Paragraph(esc(story["dialogues"] or "(none)"), body_style),
        Spacer(1, 20),
        Paragraph("Exported from Film Creator", body_style),
    ]
    doc.build(story_flow)
    return buffer.getvalue()


def call_openai(system_prompt: str, user_prompt: str) -> tuple[bool, str]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return False, (
            "AI Story Assistant is not configured yet. "
            "Ask the site owner to set the OPENAI_API_KEY environment variable."
        )

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.85,
            max_tokens=1200,
        )
        content = (response.choices[0].message.content or "").strip()
        if not content:
            return False, "The AI returned an empty response. Please try again."
        return True, content
    except Exception as exc:  # noqa: BLE001 — surface friendly error to users
        app.logger.exception("OpenAI request failed")
        return False, f"AI request failed: {exc}"


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(_e):
    return render_template(
        "error.html", code=500, message="Something went wrong on our side."
    ), 500


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("studio"))

    if request.method == "POST":
        username = clean_text(request.form.get("username"), 30)
        email = clean_text(request.form.get("email"), 120).lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        errors = validate_registration(username, email, password, confirm)
        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("signup.html", username=username, email=email)

        db = get_db()
        try:
            db.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'user', ?)
                """,
                (
                    username,
                    email,
                    generate_password_hash(password),
                    datetime.utcnow().isoformat(timespec="seconds"),
                ),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username or email is already registered.", "error")
            return render_template("signup.html", username=username, email=email)

        user = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        session.clear()
        session["user_id"] = user["id"]
        flash("Welcome to Film Creator! Your account is ready.", "success")
        return redirect(url_for("studio"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("studio"))

    if request.method == "POST":
        identifier = clean_text(request.form.get("identifier"), 120)
        password = request.form.get("password") or ""
        next_url = request.form.get("next") or request.args.get("next") or ""

        user = get_db().execute(
            """
            SELECT id, password_hash FROM users
            WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
            """,
            (identifier, identifier.lower()),
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "error")
            return render_template("login.html", identifier=identifier, next=next_url)

        session.clear()
        session["user_id"] = user["id"]
        flash("You are logged in.", "success")

        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("studio"))

    return render_template(
        "login.html", next=request.args.get("next", "")
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Story Writing Studio
# ---------------------------------------------------------------------------

@app.route("/studio")
@login_required
def studio():
    user = current_user()
    stories = get_db().execute(
        """
        SELECT id, title, genre, updated_at, created_at
        FROM stories WHERE user_id = ?
        ORDER BY updated_at DESC
        """,
        (user["id"],),
    ).fetchall()
    return render_template("studio.html", stories=stories)


@app.route("/studio/new", methods=["GET", "POST"])
@login_required
def story_new():
    user = current_user()
    if request.method == "POST":
        title = clean_text(request.form.get("title"), MAX_TITLE_LEN)
        genre = clean_text(request.form.get("genre"), MAX_GENRE_LEN)
        characters = clean_text(request.form.get("characters"), MAX_FIELD_LEN)
        scenes = clean_text(request.form.get("scenes"), MAX_FIELD_LEN)
        dialogues = clean_text(request.form.get("dialogues"), MAX_FIELD_LEN)

        if not title:
            flash("Story title is required.", "error")
            return render_template(
                "studio_edit.html",
                story=None,
                form={
                    "title": title,
                    "genre": genre,
                    "characters": characters,
                    "scenes": scenes,
                    "dialogues": dialogues,
                },
            )

        if genre not in VALID_GENRES:
            genre = "Other"

        now = datetime.utcnow().isoformat(timespec="seconds")
        cur = get_db().execute(
            """
            INSERT INTO stories
            (user_id, title, genre, characters, scenes, dialogues, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user["id"], title, genre, characters, scenes, dialogues, now, now),
        )
        get_db().commit()
        flash("Story saved.", "success")
        return redirect(url_for("story_edit", story_id=cur.lastrowid))

    return render_template("studio_edit.html", story=None, form=None)


@app.route("/studio/<int:story_id>", methods=["GET", "POST"])
@login_required
def story_edit(story_id: int):
    user = current_user()
    story = get_owned_story(story_id, user["id"])
    if not story:
        abort(404)

    if request.method == "POST":
        title = clean_text(request.form.get("title"), MAX_TITLE_LEN)
        genre = clean_text(request.form.get("genre"), MAX_GENRE_LEN)
        characters = clean_text(request.form.get("characters"), MAX_FIELD_LEN)
        scenes = clean_text(request.form.get("scenes"), MAX_FIELD_LEN)
        dialogues = clean_text(request.form.get("dialogues"), MAX_FIELD_LEN)
        autosave = request.form.get("autosave") == "1"

        if not title:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(ok=False, error="Story title is required."), 400
            flash("Story title is required.", "error")
            return render_template(
                "studio_edit.html",
                story=story,
                form={
                    "title": title,
                    "genre": genre,
                    "characters": characters,
                    "scenes": scenes,
                    "dialogues": dialogues,
                },
            )

        if genre not in VALID_GENRES:
            genre = "Other"

        now = datetime.utcnow().isoformat(timespec="seconds")
        get_db().execute(
            """
            UPDATE stories
            SET title = ?, genre = ?, characters = ?, scenes = ?, dialogues = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (title, genre, characters, scenes, dialogues, now, story_id, user["id"]),
        )
        get_db().commit()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or autosave:
            return jsonify(ok=True, updated_at=now, message="Saved.")

        flash("Story updated.", "success")
        return redirect(url_for("story_edit", story_id=story_id))

    return render_template("studio_edit.html", story=story, form=None)


@app.route("/studio/<int:story_id>/delete", methods=["POST"])
@login_required
def story_delete(story_id: int):
    user = current_user()
    story = get_owned_story(story_id, user["id"])
    if not story:
        abort(404)
    get_db().execute(
        "DELETE FROM stories WHERE id = ? AND user_id = ?",
        (story_id, user["id"]),
    )
    get_db().commit()
    flash("Story deleted.", "success")
    return redirect(url_for("studio"))


@app.route("/studio/<int:story_id>/download.txt")
@login_required
def story_download_txt(story_id: int):
    user = current_user()
    story = get_owned_story(story_id, user["id"])
    if not story:
        abort(404)
    text = story_to_text(story)
    safe_name = re.sub(r"[^\w\-]+", "_", story["title"])[:60] or "story"
    return Response(
        text,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}.txt"'
        },
    )


@app.route("/studio/<int:story_id>/download.pdf")
@login_required
def story_download_pdf(story_id: int):
    user = current_user()
    story = get_owned_story(story_id, user["id"])
    if not story:
        abort(404)
    try:
        pdf_bytes = story_to_pdf(story)
    except Exception:  # noqa: BLE001
        app.logger.exception("PDF export failed")
        flash("PDF export failed. Try downloading as TXT instead.", "error")
        return redirect(url_for("story_edit", story_id=story_id))

    safe_name = re.sub(r"[^\w\-]+", "_", story["title"])[:60] or "story"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}.pdf"'
        },
    )


# ---------------------------------------------------------------------------
# AI Story Assistant
# ---------------------------------------------------------------------------

AI_MODES = {
    "idea": "Generate a fresh movie story idea with a logline and hook.",
    "plot": "Generate a structured plot outline with beginning, middle, and end.",
    "character": "Generate vivid character descriptions including motivation and conflict.",
    "scene": "Generate cinematic scene descriptions with setting, mood, and action.",
    "dialogue": "Generate natural, character-driven dialogue for a film scene.",
}


@app.route("/ai", methods=["GET", "POST"])
@login_required
def ai_assistant():
    result = None
    error = None
    form_data = {
        "mode": "idea",
        "genre": "Drama",
        "prompt": "",
    }

    if request.method == "POST":
        mode = clean_text(request.form.get("mode"), 40)
        genre = clean_text(request.form.get("genre"), MAX_GENRE_LEN)
        prompt = clean_text(request.form.get("prompt"), MAX_PROMPT_LEN)
        form_data = {"mode": mode, "genre": genre, "prompt": prompt}

        if mode not in AI_MODES:
            flash("Invalid generation mode.", "error")
        elif not prompt:
            flash("Please enter a prompt describing what you want.", "error")
        elif genre not in VALID_GENRES:
            flash("Please choose a valid genre.", "error")
        else:
            system_prompt = (
                "You are a professional film screenwriter assisting creators on Film Creator. "
                f"Focus on the {genre} genre. {AI_MODES[mode]} "
                "Keep the response practical, vivid, and ready to paste into a screenplay draft. "
                "Do not include disclaimers about being an AI."
            )
            ok, message = call_openai(system_prompt, prompt)
            if ok:
                result = message
            else:
                error = message

    return render_template(
        "ai_assistant.html",
        modes=AI_MODES,
        form_data=form_data,
        result=result,
        error=error,
    )


# ---------------------------------------------------------------------------
# Admin dashboard
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute(
        """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               COUNT(s.id) AS story_count
        FROM users u
        LEFT JOIN stories s ON s.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
        """
    ).fetchall()
    stories = db.execute(
        """
        SELECT s.id, s.title, s.genre, s.updated_at, u.username
        FROM stories s
        JOIN users u ON u.id = s.user_id
        ORDER BY s.updated_at DESC
        LIMIT 100
        """
    ).fetchall()
    stats = {
        "users": db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
        "stories": db.execute("SELECT COUNT(*) AS c FROM stories").fetchone()["c"],
        "admins": db.execute(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'"
        ).fetchone()["c"],
    }
    return render_template(
        "admin.html", users=users, stories=stories, stats=stats
    )


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_set_role(user_id: int):
    admin = current_user()
    new_role = clean_text(request.form.get("role"), 20)
    if new_role not in ("user", "admin"):
        flash("Invalid role.", "error")
        return redirect(url_for("admin_dashboard"))

    target = get_db().execute(
        "SELECT id, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if target["id"] == admin["id"] and new_role != "admin":
        flash("You cannot remove your own admin role.", "error")
        return redirect(url_for("admin_dashboard"))

    if target["role"] == "admin" and new_role == "user":
        admin_count = get_db().execute(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'"
        ).fetchone()["c"]
        if admin_count <= 1:
            flash("Cannot demote the last admin.", "error")
            return redirect(url_for("admin_dashboard"))

    get_db().execute(
        "UPDATE users SET role = ? WHERE id = ?", (new_role, user_id)
    )
    get_db().commit()
    flash("User role updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id: int):
    admin = current_user()
    if user_id == admin["id"]:
        flash("You cannot delete your own account from the admin panel.", "error")
        return redirect(url_for("admin_dashboard"))

    target = get_db().execute(
        "SELECT id, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if target["role"] == "admin":
        admin_count = get_db().execute(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'"
        ).fetchone()["c"]
        if admin_count <= 1:
            flash("Cannot delete the last admin.", "error")
            return redirect(url_for("admin_dashboard"))

    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    get_db().commit()
    flash("User and their stories were deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/stories/<int:story_id>/delete", methods=["POST"])
@admin_required
def admin_delete_story(story_id: int):
    row = get_db().execute(
        "SELECT id FROM stories WHERE id = ?", (story_id,)
    ).fetchone()
    if not row:
        flash("Story not found.", "error")
        return redirect(url_for("admin_dashboard"))
    get_db().execute("DELETE FROM stories WHERE id = ?", (story_id,))
    get_db().commit()
    flash("Story removed for moderation.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# Health / init
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        return jsonify(status="ok", database="connected")
    except Exception as exc:  # noqa: BLE001
        return jsonify(status="error", detail=str(exc)), 500


with app.app_context():
    init_db()


if __name__ == "__main__":
    # debug=True is for local development only
    app.run(host="127.0.0.1", port=5000, debug=True)
