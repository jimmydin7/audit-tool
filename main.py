from flask import Flask, render_template, redirect, request, url_for, session
from dotenv import load_dotenv
from supabase import create_client
import json
import os
from urllib.parse import urlparse
from scraper.scraper import analyze


load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = 'supersecretkey'
public_base_url = os.environ.get("PUBLIC_SITE_URL") or os.environ.get("APP_BASE_URL")
if public_base_url and public_base_url.startswith("https://"):
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def store_post_login_redirect(target_path):
    if not target_path:
        return
    session["post_login_redirect"] = target_path


def get_oauth_url(provider, redirect_url):
    if provider not in ("google", "github"):
        return {"success": False, "error": "Unsupported OAuth provider."}
    try:
        response = supabase.auth.sign_in_with_oauth({
            "provider": provider,
            "options": {
                "redirect_to": redirect_url
            }
        })
        return {"success": True, "url": response.url}
    except Exception as e:
        print(f"{provider.title()} OAuth failed:", e)
        return {"success": False, "error": f"Failed to initiate {provider.title()} sign-in."}


def exchange_code_for_session(code):
    try:
        response = supabase.auth.exchange_code_for_session({"auth_code": code})
        if response.user is None:
            return {"success": False, "error": "Failed to exchange code for session."}
        return {
            "success": True,
            "user": response.user,
            "access_token": response.session.access_token,
            "refresh_token": response.session.refresh_token
        }
    except Exception as e:
        print("Code exchange failed:", e)
        return {"success": False, "error": "Failed to complete authentication."}


def set_session(access_token, refresh_token):
    response = supabase.auth.set_session(access_token=access_token, refresh_token=refresh_token)
    return response.user


def update_user_metadata(access_token, refresh_token, first_name, last_name):
    try:
        supabase.auth.set_session(access_token=access_token, refresh_token=refresh_token)
        response = supabase.auth.update_user({
            "data": {
                "first_name": first_name,
                "last_name": last_name
            }
        })
        if response.user is None:
            return {"success": False, "error": "Failed to update profile."}
        new_session = supabase.auth.get_session()
        return {
            "success": True,
            "user": response.user,
            "access_token": new_session.access_token,
            "refresh_token": new_session.refresh_token
        }
    except Exception as e:
        print("Update user metadata failed:", e)
        return {"success": False, "error": "Failed to update profile. Please try again."}


def get_public_base_url():
    if public_base_url:
        return public_base_url.rstrip("/")
    return request.host_url.rstrip("/")


@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))


def start_oauth(provider):
    redirect_url = get_public_base_url() + "/auth/callback"
    result = get_oauth_url(provider, redirect_url)
    if result['success']:
        return redirect(result['url'])
    return render_template("auth/login.html", error=result.get("error") or "Authentication failed.")


@app.route("/auth/<provider>")
def oauth_login(provider):
    if provider not in ("google", "github"):
        return redirect("/login")
    return start_oauth(provider)


@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    access_token = request.args.get("access_token")
    refresh_token = request.args.get("refresh_token")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    if error:
        print(f"OAuth error: {error} - {error_description}")
        return render_template("auth/login.html", error=error_description or "Authentication failed.")

    if code:
        try:
            result = exchange_code_for_session(code)
            if not result['success']:
                return render_template("auth/login.html", error=result.get('error', 'Authentication failed.'))
            user = result['user']
            session['access_token'] = result.get('access_token')
            session['refresh_token'] = result.get('refresh_token')
        except Exception as e:
            print(f"Code exchange error: {e}")
            return render_template("auth/login.html", error="Failed to complete sign-in. Please try again.")
    elif access_token:
        try:
            user = set_session(access_token=access_token, refresh_token=refresh_token)
            session['access_token'] = access_token
            session['refresh_token'] = refresh_token
        except Exception as e:
            print(f"Set session error: {e}")
            return render_template("auth/login.html", error="Failed to complete sign-in. Please try again.")
    else:
        return render_template("auth/callback.html")

    try:
        full_name = (
            user.user_metadata.get("full_name")
            or user.user_metadata.get("name")
            or user.user_metadata.get("user_name")
            or ""
        )
        name_parts = full_name.split() if full_name else []

        session['user'] = {
            "id": user.id,
            "email": user.email,
            "first_name": user.user_metadata.get("first_name") or (name_parts[0] if name_parts else None),
            "last_name": user.user_metadata.get("last_name") or (" ".join(name_parts[1:]) if len(name_parts) > 1 else None),
            "avatar_url": user.user_metadata.get("avatar_url") or user.user_metadata.get("picture"),
            "verified": True,
            "onboarding_complete": True
        }

        redirect_target = session.pop("post_login_redirect", None)
        return redirect(redirect_target or '/app/dashboard')

    except Exception as e:
        print("Auth callback error:", e)
        return render_template("auth/login.html", error="Failed to complete sign-in. Please try again.")


@app.route('/signup')
def signup():
    return redirect('/login')


@app.route('/login')
def login():
    if session.get("user"):
        redirect_target = session.pop("post_login_redirect", None)
        return redirect(redirect_target or "/app/dashboard")
    return render_template('auth/login.html')


@app.route('/account', methods=['GET', 'POST'])
def account():
    user = session.get('user')
    if not user:
        return redirect('/login')

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()

        if not first_name:
            return render_template('auth/account.html', user=user, error="First name is required.")

        access_token = session.get('access_token')
        refresh_token = session.get('refresh_token')

        if not access_token or not refresh_token:
            return render_template('auth/account.html', user=user, error="Session expired. Please log in again.")

        result = update_user_metadata(
            access_token=access_token,
            refresh_token=refresh_token,
            first_name=first_name,
            last_name=last_name
        )

        if not result['success']:
            return render_template('auth/account.html', user=user, error=result['error'])

        session['user']['first_name'] = first_name
        session['user']['last_name'] = last_name
        session['access_token'] = result.get('access_token')
        session['refresh_token'] = result.get('refresh_token')
        session.modified = True

        return render_template('auth/account.html', user=session.get('user'), success="Profile updated successfully.")

    return render_template('auth/account.html', user=user)


@app.route('/logout')
def logout():
    session.pop("user", None)
    session.pop("access_token", None)
    session.pop("refresh_token", None)
    return redirect(url_for("index"))


def normalize_url(raw_url: str):
    if not raw_url:
        return None
    url = raw_url.strip()
    if not url:
        return None
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


@app.route('/app/dashboard')
def dashboard():
    user = session.get("user")
    if not user:
        return redirect('/login')
    return render_template('app/dashboard.html', user=user)


@app.route('/app/new', methods=['GET', 'POST'])
def new_audit():
    user = session.get("user")
    if not user:
        store_post_login_redirect(request.full_path.rstrip("?"))
        return redirect('/login')

    raw_url = request.values.get('url', '').strip()
    url = normalize_url(raw_url) if raw_url else None
    if raw_url and not url:
        return render_template('app/new.html', user=user, error="Please enter a valid URL.")

    if url:
        return render_template('app/processing.html', user=user, url=url)

    return render_template('app/new.html', user=user)


@app.route('/app/results', methods=['GET', 'POST'])
def audit_results():
    user = session.get("user")
    if not user:
        return redirect('/login')
    raw_url = request.values.get('url', '')
    url = normalize_url(raw_url)
    if not url:
        return redirect(url_for('index', error="Please enter a valid URL (example: https://example.com)."))
    try:
        audit = analyze(url)
    except Exception as exc:
        print(f"Audit failed for {url}: {exc}")
        return redirect(url_for('index', error="Audit failed. Please try again."))
    audit_json = json.dumps(audit, indent=2)
    return render_template('app/results.html', audit=audit, audit_json=audit_json)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1700)
