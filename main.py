from flask import Flask, render_template, redirect, request, url_for, session, jsonify
from dotenv import load_dotenv
from supabase import create_client
import json
import os
from urllib.parse import urlparse
from scraper.scraper import analyze, analyze_html, generate_llm_prompt, ScrapeError
import threading
import uuid
import time
from collections import deque
from datetime import datetime, timezone, timedelta
import stripe
import requests


AUDIT_JOBS = {}
FEATURE_SUGGEST_TIMES = {}
#RATE_LIMITS = {}
#RATE_LIMIT_WINDOW_SEC = 60
#RATE_LIMIT_MAX_REQUESTS = 5
SCAN_LIMITS = {"free": 1, "paid": 15}
DISCORD_CONTACT_WEBHOOK = "https://discord.com/api/webhooks/1470306076694941719/ClTudUO8_Lu_I40i1t0P51oMcKcVtxzSlmdPUF-cy7lYy9niqsvZ4MNRaVQqw0JGpLYL"
DISCORD_SCAN_WEBHOOK = "https://discord.com/api/webhooks/1470306210036318231/LVGfUqdLSniOKg3Cg3Udzb_q4dkuURHPXxZ0KwiyIMefUcahmUizPmb2NgHDITTQ52Xc"
DISCORD_FEATURE_WEBHOOK = "https://discord.com/api/webhooks/1473046786997358752/3YJeqGNe5of7wykVUh-3m_JycKVmuqtP5YSIHnNqr6A7EWD3jwDSVz2_a2xDWNS_UiuT"


load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.permanent_session_lifetime = timedelta(days=30)
public_base_url = os.environ.get("PUBLIC_SITE_URL") or os.environ.get("APP_BASE_URL")
STRIPE_SECRET = os.environ.get("STRIPE_SECRET")
STRIPE_PUBLISHABLE = os.environ.get("STRIPE_PUBLISHABLE")
STRIPE_PRODUCT_ID = os.environ.get("STRIPE_PRODUCT_ID", "prod_TwhpvMMBfJyNnP")
if STRIPE_SECRET:
    stripe.api_key = STRIPE_SECRET
if public_base_url and public_base_url.startswith("https://"):
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _is_down_mode_enabled() -> bool:
    value = (os.environ.get("DOWN") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


@app.before_request
def maintenance_mode_guard():
    if not _is_down_mode_enabled():
        return None
    if request.endpoint == "static":
        return None
    return render_template("maintenance.html"), 503


def store_post_login_redirect(target_path):
    if not target_path:
        return
    if "/app/upload" in target_path:
        session["post_login_redirect"] = "/app/dashboard"
        return
    session["post_login_redirect"] = target_path


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


#def _rate_limited(key: str):
#    now = time.time()
#    q = RATE_LIMITS.get(key)
#    if q is None:
#        q = deque()
#        RATE_LIMITS[key] = q
#    while q and now - q[0] > RATE_LIMIT_WINDOW_SEC:
#        q.popleft()
#    if len(q) >= RATE_LIMIT_MAX_REQUESTS:
#        return True
#    q.append(now)
#    return False


def _sanitize_audit_for_public(audit):
    source = audit or {}
    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            return "Lorem ipsum"
        if isinstance(value, (int, float)):
            return 0
        return value

    masked = scrub(source)

    # Preserve real top-section fields
    masked["url"] = source.get("url")
    masked["scanned_at"] = source.get("scanned_at")
    if isinstance(masked.get("scores"), dict) and isinstance(source.get("scores"), dict):
        if isinstance(masked["scores"].get("overall"), dict) and isinstance(source.get("scores").get("overall"), dict):
            masked["scores"]["overall"]["grade"] = source["scores"]["overall"].get("grade")
            masked["scores"]["overall"]["score"] = source["scores"]["overall"].get("score") or 0
            masked["scores"]["overall"]["summary"] = "Lorem ipsum dolor sit amet."
    if isinstance(masked.get("metadata"), dict) and isinstance(source.get("metadata"), dict):
        if isinstance(masked["metadata"].get("technology_stack"), dict) and isinstance(source.get("metadata").get("technology_stack"), dict):
            masked["metadata"]["technology_stack"]["framework"] = source["metadata"]["technology_stack"].get("framework")
            masked["metadata"]["technology_stack"]["analytics"] = source["metadata"]["technology_stack"].get("analytics") or []
    masked["scan_duration_ms"] = source.get("scan_duration_ms") or 0
    masked["domain_rating"] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
    return masked

    
def _normalize_plan(value):
    if not value:
        return "free"
    plan = str(value).strip().lower()
    if plan in {"paid", "pro", "premium", "active", "trialing", "trial"}:
        return "paid"
    return "free"


def _get_user_stats(user_id):
    scans_this_month = 0
    plan = "free"
    try:
        resp = supabase.table("user_stats").select("scans_this_month,subscription_type").eq("user_id", user_id).single().execute()
        row = resp.data or {}
        scans_this_month = row.get("scans_this_month") or 0
        plan = _normalize_plan(row.get("subscription_type"))
    except Exception:
        scans_this_month = 0
        plan = "free"

    if plan == "free":
        try:
            sub_resp = supabase.table("subscriptions").select("status").eq("user_id", user_id).limit(1).execute()
            if sub_resp.data:
                status = (sub_resp.data[0].get("status") or "").lower()
                if status in {"active", "trialing"}:
                    plan = "paid"
        except Exception:
            pass

    return {"scans_this_month": scans_this_month, "plan": plan}

ADMIN_EMAILS = ["dimdinias@gmail.com"]


def _format_domain(url):
    if not url:
        return "unknown"
    return url.replace("https://", "").replace("http://", "").split("/")[0] or "unknown"


def _send_scan_webhook(*, status, reason=None, url=None, user_id=None, plan=None, audit_id=None, scan_cost=None, duration_ms=None, model_used=None, user_name=None, html_lines=None, html_chars=None):
    try:
        domain = _format_domain(url)
        title = "Audit Completed" if status == "completed" else "Audit Blocked"
        color = 3066993 if status == "completed" else 15158332
        fields = [
            {"name": "Status", "value": status.replace("_", " ").title(), "inline": True},
            {"name": "Domain", "value": domain, "inline": True},
        ]
        if reason:
            fields.append({"name": "Reason", "value": reason.replace("_", " ").title(), "inline": False})
        if plan:
            fields.append({"name": "Plan", "value": plan, "inline": True})
        if user_id:
            fields.append({"name": "User ID", "value": user_id, "inline": True})
        if audit_id:
            fields.append({"name": "Audit ID", "value": audit_id, "inline": True})
            fields.append({"name": "Audit Link", "value": "https://fixmyland.ing/share/" + audit_id, "inline": True})
        if scan_cost is not None:
            fields.append({"name": "Scan Cost", "value": str(scan_cost), "inline": True})
        if duration_ms is not None:
            fields.append({"name": "Duration", "value": f"{duration_ms} ms", "inline": True})
        if model_used:
            fields.append({"name": "Model", "value": model_used, "inline": True})
        if user_name:
            fields.append({"name": "User", "value": user_name, "inline": True})
        if html_lines is not None:
            fields.append({"name": "HTML Lines", "value": f"{html_lines:,}", "inline": True})
        if html_chars is not None:
            fields.append({"name": "HTML Chars", "value": f"{html_chars:,}", "inline": True})

        requests.post(DISCORD_SCAN_WEBHOOK, json={
            "embeds": [{
                "title": title,
                "color": color,
                "fields": fields
            }]
        }, timeout=5)
    except Exception:
        pass



def run_audit(job_id, url):
    try:
        user_id = AUDIT_JOBS[job_id].get("user_id")
        user_name = AUDIT_JOBS[job_id].get("user_name")
        plan = "free"
        if user_id:
            stats = _get_user_stats(user_id)
            plan = stats.get("plan") or "free"
        def _on_fallback():
            AUDIT_JOBS[job_id]["fallback"] = True

        result = analyze(url, plan=plan, on_fallback=_on_fallback)

        if result.get("_empty_page"):
            result.pop("_empty_page", None)
            result.pop("_model_used", None)
            result.pop("_scan_cost", None)
            result.pop("_html_lines", None)
            result.pop("_html_chars", None)
            AUDIT_JOBS[job_id]["status"] = "blocked_page"
            AUDIT_JOBS[job_id]["error"] = "The website returned a protected or empty page that we can't audit automatically."
            _send_scan_webhook(
                status="blocked",
                reason="blocked_page: AI detected shell/protected HTML",
                url=url,
                user_id=user_id,
                plan=plan,
                user_name=user_name
            )
            return

        model_used = result.pop("_model_used", None)
        scan_cost = result.pop("_scan_cost", 1)
        html_lines = result.pop("_html_lines", None)
        html_chars = result.pop("_html_chars", None)
        upgrade_required = (result.get("metadata") or {}).get("upgrade_required", False)
        model_limit = (result.get("metadata") or {}).get("model_limit", False)
        audit_id = None
        if user_id and not upgrade_required:
            try:
                insert_resp = supabase.table("audits").insert({
                    "user_id": user_id,
                    "url": url,
                    "result": result
                }).execute()
                if insert_resp.data:
                    audit_id = insert_resp.data[0].get("id")
            except Exception as e:
                print("Failed to save audit:", e)
            if scan_cost > 1:
                try:
                    extra = scan_cost - 1
                    supabase.table("user_stats").update({
                        "scans_this_month": stats["scans_this_month"] + extra
                    }).eq("user_id", user_id).execute()
                except Exception as e:
                    print("Failed to add extra scan cost:", e)
        AUDIT_JOBS[job_id]["status"] = "done"
        AUDIT_JOBS[job_id]["result"] = result
        AUDIT_JOBS[job_id]["audit_id"] = audit_id
        if upgrade_required:
            status = "blocked"
            reason = "free_tier_too_large"
        elif model_limit:
            status = "blocked"
            reason = "paid_model_limit_exceeded"
        else:
            status = "completed"
            reason = None
        _send_scan_webhook(
            status=status,
            reason=reason,
            url=url,
            user_id=user_id,
            plan=plan,
            audit_id=audit_id,
            scan_cost=scan_cost,
            duration_ms=result.get("scan_duration_ms"),
            model_used=model_used,
            user_name=user_name,
            html_lines=html_lines,
            html_chars=html_chars
        )
    except ScrapeError as e:
        AUDIT_JOBS[job_id]["status"] = "error"
        AUDIT_JOBS[job_id]["error"] = str(e)
        _send_scan_webhook(
            status="error",
            reason=f"scrape_failed: {str(e)[:180]}",
            url=AUDIT_JOBS[job_id].get("url"),
            user_id=AUDIT_JOBS[job_id].get("user_id"),
            plan=plan if 'plan' in dir() else None,
            user_name=AUDIT_JOBS[job_id].get("user_name")
        )
    except Exception as e:
        AUDIT_JOBS[job_id]["status"] = "error"
        AUDIT_JOBS[job_id]["error"] = str(e)
        _send_scan_webhook(
            status="error",
            reason=str(e)[:200],
            url=AUDIT_JOBS[job_id].get("url"),
            user_id=AUDIT_JOBS[job_id].get("user_id"),
            user_name=AUDIT_JOBS[job_id].get("user_name")
        )


def run_audit_with_html(job_id, url, html_code):
    try:
        user_id = AUDIT_JOBS[job_id].get("user_id")
        user_name = AUDIT_JOBS[job_id].get("user_name")
        plan = "free"
        if user_id:
            stats = _get_user_stats(user_id)
            plan = stats.get("plan") or "free"
        def _on_fallback():
            AUDIT_JOBS[job_id]["fallback"] = True

        result = analyze_html(html_code, url, plan=plan, on_fallback=_on_fallback)
        model_used = result.pop("_model_used", None)
        scan_cost = result.pop("_scan_cost", 1)
        html_lines = result.pop("_html_lines", None)
        html_chars = result.pop("_html_chars", None)
        upgrade_required = (result.get("metadata") or {}).get("upgrade_required", False)
        audit_id = None
        if user_id and not upgrade_required:
            try:
                insert_resp = supabase.table("audits").insert({
                    "user_id": user_id,
                    "url": url,
                    "result": result
                }).execute()
                if insert_resp.data:
                    audit_id = insert_resp.data[0].get("id")
            except Exception as e:
                print("Failed to save audit:", e)
        AUDIT_JOBS[job_id]["status"] = "done"
        AUDIT_JOBS[job_id]["result"] = result
        AUDIT_JOBS[job_id]["audit_id"] = audit_id
        _send_scan_webhook(
            status="completed",
            url=url,
            user_id=user_id,
            plan=plan,
            audit_id=audit_id,
            scan_cost=scan_cost,
            duration_ms=result.get("scan_duration_ms"),
            model_used=model_used,
            user_name=user_name,
            html_lines=html_lines,
            html_chars=html_chars
        )
    except Exception as e:
        AUDIT_JOBS[job_id]["status"] = "error"
        AUDIT_JOBS[job_id]["error"] = str(e)


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
    base = public_base_url or request.host_url.rstrip("/")
    if not base.startswith("http://") and not base.startswith("https://"):
        base = "https://" + base
    return base.rstrip("/")


def get_or_create_stripe_customer(user):
    existing_row = None
    try:
        resp = supabase.table("subscriptions").select("id,stripe_customer_id").eq("user_id", user["id"]).limit(1).execute()
        if resp.data:
            existing_row = resp.data[0]
            existing = existing_row.get("stripe_customer_id")
            if existing:
                return existing
    except Exception as e:
        print("Failed to read subscription:", e)

    customer = stripe.Customer.create(
        email=user.get("email"),
        metadata={"user_id": user.get("id")}
    )
    try:
        if existing_row:
            supabase.table("subscriptions").update({
                "stripe_customer_id": customer.id
            }).eq("id", existing_row.get("id")).execute()
        else:
            supabase.table("subscriptions").insert({
                "user_id": user["id"],
                "stripe_customer_id": customer.id
            }).execute()
    except Exception as e:
        print("Failed to save customer id:", e)
    return customer.id


def get_monthly_price_id():
    prices = stripe.Price.list(product=STRIPE_PRODUCT_ID, active=True, limit=1)
    if not prices.data:
        raise ValueError("No active Stripe price found for product.")
    return prices.data[0].id



def refresh_subscription_status(user_id):
    if not STRIPE_SECRET:
        return
    try:
        resp = supabase.table("subscriptions").select("stripe_subscription_id, stripe_customer_id, status").eq("user_id", user_id).limit(1).execute()
        if not resp.data:
            return
        row = resp.data[0]
        subscription_id = row.get("stripe_subscription_id")
        if not subscription_id:
            return
        subscription = stripe.Subscription.retrieve(subscription_id)
        status = subscription.status
        current_period_end = None
        if subscription.get("current_period_end"):
            current_period_end = datetime.fromtimestamp(subscription["current_period_end"], tz=timezone.utc).isoformat()
        supabase.table("subscriptions").update({
            "stripe_customer_id": row.get("stripe_customer_id"),
            "stripe_subscription_id": subscription_id,
            "status": status,
            "current_period_end": current_period_end
        }).eq("user_id", user_id).execute()
    except Exception as e:
        print("Failed to refresh subscription:", e)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        if not name or not email or not message:
            return render_template('contact.html', error="Please fill in all fields.")
        try:
            requests.post(DISCORD_CONTACT_WEBHOOK, json={
                "embeds": [{
                    "title": "New Contact Message",
                    "color": 16751790,
                    "fields": [
                        {"name": "Name", "value": name, "inline": True},
                        {"name": "Email", "value": email, "inline": True},
                        {"name": "Message", "value": message},
                    ]
                }]
            }, timeout=10)
            return render_template('contact.html', success=True)
        except Exception:
            return render_template('contact.html', error="Failed to send message. Please try again.")
    return render_template('contact.html')


@app.route('/api/suggest-feature', methods=['POST'])
def suggest_feature():
    user = session.get("user")
    if not user:
        return jsonify({"success": False, "error": "You must be logged in."}), 401
    uid = user.get("id") or _client_ip()
    now = time.time()
    q = FEATURE_SUGGEST_TIMES.get(uid)
    if q is None:
        q = deque()
        FEATURE_SUGGEST_TIMES[uid] = q
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= 3:
        return jsonify({"success": False, "error": "You can only submit 3 suggestions per hour. Try again later."}), 429
    data = request.get_json() or {}
    feature = (data.get("feature") or "").strip()
    if not feature:
        return jsonify({"success": False, "error": "Please describe the feature."}), 400
    q.append(now)
    name = f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or "Unknown"
    email = user.get("email") or "Unknown"
    try:
        requests.post(DISCORD_FEATURE_WEBHOOK, json={
            "embeds": [{
                "title": "Feature Suggestion",
                "color": 7506394,
                "fields": [
                    {"name": "Name", "value": name, "inline": True},
                    {"name": "Email", "value": email, "inline": True},
                    {"name": "Feature", "value": feature[:1024]},
                ]
            }]
        }, timeout=10)
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Failed to send suggestion. Please try again."}), 500


@app.route('/terms')
def terms():
    return render_template('legal/terms.html')

@app.route('/privacy')
def privacy():
    return render_template('legal/privacy.html')

@app.route('/')
def index():
    user = session.get('user')
    plan = "free"
    if user:
        stats = _get_user_stats(user["id"])
        plan = stats.get("plan", "free")
    return render_template('index.html', user=user, plan=plan)


def start_oauth(provider):
    store_post_login_redirect("/app/dashboard")
    redirect_url = get_public_base_url() + "/auth/callback"
    result = get_oauth_url(provider, redirect_url)
    if result['success']:
        return redirect(result['url'])
    return render_template("auth/login.html", error=result.get("error") or "Authentication failed.")


@app.route("/auth/<provider>")
def oauth_login(provider):
    if provider not in ("google", "github"):
        return redirect("/login")
    shared_id = request.args.get("shared")
    if shared_id:
        session["shared_audit_id"] = shared_id
        session["post_login_redirect"] = f"/app/dashboard?shared={shared_id}"
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

        session.permanent = True
        session['user'] = {
            "id": user.id,
            "email": user.email,
            "first_name": user.user_metadata.get("first_name") or (name_parts[0] if name_parts else None),
            "last_name": user.user_metadata.get("last_name") or (" ".join(name_parts[1:]) if len(name_parts) > 1 else None),
            "avatar_url": user.user_metadata.get("avatar_url") or user.user_metadata.get("picture"),
            "verified": True,
            "onboarding_complete": True
        }
        try:
            supabase.table("profiles").upsert({
                "id": user.id,
                "email": user.email
            }, on_conflict="id").execute()
        except Exception as e:
            print("Profile upsert failed:", e)

        redirect_target = session.pop("post_login_redirect", None)
        return redirect(redirect_target or '/app/dashboard')

    except Exception as e:
        print("Auth callback error:", e)
        return render_template("auth/login.html", error="Failed to complete sign-in. Please try again.")

@app.route('/tools/keywords')
def keywords_tool():
    return render_template('tools/keywords.html')

@app.route('/tools/link_counter')
def links_tool():
    return render_template('tools/linkcounter.html')

@app.route('/tools/meta_tag_viewer')
def meta_tag_view():
    return render_template('tools/meta_tag_viewer.html')

@app.route('/signup')
def signup():
    shared_id = request.args.get("shared")
    if shared_id:
        session["shared_audit_id"] = shared_id
        session["post_login_redirect"] = f"/app/dashboard?shared={shared_id}"
    store_post_login_redirect("/app/dashboard")
    return redirect('/login')


@app.route('/login')
def login():
    if session.get("user"):
        redirect_target = session.pop("post_login_redirect", None)
        return redirect(redirect_target or "/app/dashboard")
    shared_id = request.args.get("shared")
    if shared_id:
        session["shared_audit_id"] = shared_id
        session["post_login_redirect"] = f"/app/dashboard?shared={shared_id}"
    return render_template('auth/login.html', shared_audit_id=shared_id)


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


@app.route("/billing/checkout")
def billing_checkout():
    user = session.get("user")
    if not user:
        store_post_login_redirect(request.path)
        return redirect("/login")
    stats = _get_user_stats(user["id"])
    if stats.get("plan") == "paid":
        return redirect("/app/dashboard?tab=billing")
    if not STRIPE_SECRET or not STRIPE_PRODUCT_ID:
        return render_template("app/error.html", error="Stripe is not configured.")
    try:
        customer_id = get_or_create_stripe_customer(user)
        price_id = get_monthly_price_id()
        base_url = get_public_base_url()
        session_obj = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            client_reference_id=user["id"],
            line_items=[{"price": price_id, "quantity": 1}],
            allow_promotion_codes=True,
            success_url=f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base_url}/billing/cancel"
        )
        return redirect(session_obj.url)
    except Exception as e:
        print("Stripe checkout failed:", e)
        return render_template("app/error.html", error="Failed to start checkout. Please try again.")


@app.route("/billing/success")
def billing_success():
    user = session.get("user")
    session_id = request.args.get("session_id")
    if not session_id:
        return render_template("app/error.html", error="Missing checkout session.")
    try:
        session_obj = stripe.checkout.Session.retrieve(session_id)
        subscription_id = session_obj.get("subscription")
        customer_id = session_obj.get("customer")
        user_id = user["id"] if user else session_obj.get("client_reference_id")
        if not user_id and customer_id:
            try:
                sub_row = supabase.table("subscriptions").select("user_id").eq("stripe_customer_id", customer_id).limit(1).execute()
                if sub_row.data:
                    user_id = sub_row.data[0].get("user_id")
            except Exception as e:
                print("Failed to resolve user by customer:", e)
        if not user_id:
            return render_template("app/error.html", error="Checkout completed, but we couldn't identify your account.")
        subscription = stripe.Subscription.retrieve(subscription_id) if subscription_id else None
        status = subscription.status if subscription else "active"
        current_period_end = None
        if subscription and subscription.get("current_period_end"):
            current_period_end = datetime.fromtimestamp(subscription["current_period_end"], tz=timezone.utc).isoformat()
        sub_row = supabase.table("subscriptions").select("id").eq("user_id", user_id).limit(1).execute()
        if sub_row.data:
            supabase.table("subscriptions").update({
                "stripe_customer_id": customer_id,
                "stripe_subscription_id": subscription_id,
                "status": status,
                "current_period_end": current_period_end
            }).eq("id", sub_row.data[0].get("id")).execute()
        else:
            supabase.table("subscriptions").insert({
                "user_id": user_id,
                "stripe_customer_id": customer_id,
                "stripe_subscription_id": subscription_id,
                "status": status,
                "current_period_end": current_period_end
            }).execute()
        if not user:
            store_post_login_redirect("/app/dashboard?tab=billing")
            return redirect("/login")
        return redirect("/app/dashboard?tab=billing")
    except Exception as e:
        print("Stripe success error:", e)
        return render_template("app/error.html", error="Checkout completed, but we couldn't update your account.")


@app.route("/billing/cancel")
def billing_cancel():
    return redirect("/app/dashboard")


@app.route("/billing/portal")
def billing_portal():
    user = session.get("user")
    if not user:
        store_post_login_redirect(request.path)
        return redirect("/login")
    if not STRIPE_SECRET:
        return render_template("app/error.html", error="Stripe is not configured.")
    try:
        resp = supabase.table("subscriptions").select("stripe_customer_id").eq("user_id", user["id"]).limit(1).execute()
        if not resp.data or not resp.data[0].get("stripe_customer_id"):
            return render_template("app/error.html", error="No Stripe customer found. Please upgrade first.")
        customer_id = resp.data[0].get("stripe_customer_id")
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=get_public_base_url() + "/app/dashboard?tab=billing"
        )
        return redirect(portal_session.url)
    except Exception as e:
        print("Stripe portal error:", e)
        return render_template("app/error.html", error="Unable to open billing portal.")


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
    active_tab = request.args.get("tab", "audits")
    shared_id = request.args.get("shared") or session.get("shared_audit_id")
    refresh_subscription_status(user["id"])
    audits = []
    subscription = None
    try:
        resp = supabase.table("audits").select("id,url,result,created_at").eq("user_id", user["id"]).order("created_at", desc=True).execute()
        audits = resp.data or []
    except Exception as e:
        print("Failed to load audits:", e)
    try:
        sub_resp = supabase.table("subscriptions").select("status,current_period_end").eq("user_id", user["id"]).limit(1).execute()
        if sub_resp.data:
            subscription = sub_resp.data[0]
    except Exception as e:
        print("Failed to load subscription:", e)

    demo_domains = {
        "stripe.com",
        "linear.app",
        "vercel.com",
        "notion.so",
        "cal.com",
        "github.com",
        "figma.com",
    }
    filtered_audits = []
    for a in audits:
        raw_url = a.get("url") or ""
        parsed = urlparse(raw_url)
        domain = parsed.netloc or raw_url.replace("https://", "").replace("http://", "").split("/")[0]
        if domain in demo_domains:
            continue
        a["is_shared"] = False
        filtered_audits.append(a)

    if audits and not filtered_audits:
        filtered_audits = []
        for a in audits:
            a["is_shared"] = False
            filtered_audits.append(a)

    if shared_id:
        try:
            shared_resp = supabase.table("audits").select("id,url,result,created_at").eq("id", shared_id).single().execute()
            shared_row = shared_resp.data
            if shared_row:
                if not any(a.get("id") == shared_row.get("id") for a in filtered_audits):
                    shared_row["is_shared"] = True
                    filtered_audits.insert(0, shared_row)
        except Exception as e:
            print("Failed to load shared audit:", e)

    stats = _get_user_stats(user["id"])
    plan = stats["plan"]
    scan_limit = SCAN_LIMITS.get(plan, 1)
    month_count = stats["scans_this_month"]

    total_audits = len(filtered_audits)
    avg_score = 0
    total_issues = 0
    if total_audits:
        scores = []
        for a in filtered_audits:
            res = a.get("result") or {}
            score = (((res.get("scores") or {}).get("overall") or {}).get("score")) or 0
            scores.append(score)
            issues_total = ((res.get("issues") or {}).get("total")) or 0
            total_issues += issues_total
        avg_score = int(round(sum(scores) / len(scores)))

    return render_template(
        'app/dashboard.html',
        user=user,
        audits=filtered_audits,
        total_audits=total_audits,
        avg_score=avg_score,
        total_issues=total_issues,
        month_count=month_count,
        plan=plan,
        scan_limit=scan_limit,
        active_tab=active_tab,
        subscription=subscription,
        shared_audit_id=shared_id
    )


@app.route('/app/new', methods=['GET', 'POST'])
def new_audit():
    user = session.get("user")
    if not user:
        store_post_login_redirect(request.full_path.rstrip("?"))
        return redirect('/login')
    refresh_subscription_status(user["id"])
    #if _rate_limited(f"audit_new:{_client_ip()}"):
    #    return render_template('app/new.html', user=user, error="Too many audits. Please wait a minute and try again.")

    raw_url = request.values.get('url', '').strip()
    url = normalize_url(raw_url) if raw_url else None
    if raw_url and not url:
        return render_template('app/new.html', user=user, error="Please enter a valid URL.")

    if url:
        # Prevent duplicate scans: if user already has a running job, redirect to it
        for existing_id, existing_job in AUDIT_JOBS.items():
            if existing_job.get("user_id") == user["id"] and existing_job["status"] == "running":
                return render_template('app/processing.html', user=user, url=existing_job.get("url"), job_id=existing_id)

        stats = _get_user_stats(user["id"])
        limit = SCAN_LIMITS.get(stats["plan"], 1)
        user_email = (user.get("email") or "").lower() if user else ""
        if user_email not in ADMIN_EMAILS:
            if stats["scans_this_month"] >= limit:
                user_name_str = f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or user.get("email") or "Unknown"
                plan_label = stats.get("plan") or "free"
                limit_val = SCAN_LIMITS.get(plan_label, 1)
                _send_scan_webhook(
                    status="blocked",
                    reason=f"limit_reached: already used {stats['scans_this_month']}/{limit_val} scans ({plan_label} plan)",
                    url=url,
                    user_id=user.get("id"),
                    plan=plan_label,
                    user_name=user_name_str
                )
                return render_template('app/new.html', user=user, quota_exceeded=True)

        if url:
            job_id = str(uuid.uuid4())
            AUDIT_JOBS[job_id] = {
                "status": "running",
                "result": None,
                "error": None,
                "url": url,
                "user_id": user["id"],
                "user_name": f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or user.get("email") or "Unknown"
            }
        thread = threading.Thread(target=run_audit, args=(job_id, url))
        thread.daemon = True
        thread.start()
        return render_template('app/processing.html', user=user, url=url, job_id=job_id)

    return render_template('app/new.html', user=user)


@app.route('/app/paste', methods=['POST'])
def paste_html_audit():
    user = session.get("user")
    if not user:
        return redirect('/login')

    raw_url = request.form.get('url', '').strip()
    url = normalize_url(raw_url) if raw_url else None
    pasted_html = request.form.get('html', '').strip()

    if not url:
        return render_template('app/paste_html.html', user=user, url=raw_url, error="Please provide a valid URL.")
    if not pasted_html or len(pasted_html) < 100:
        return render_template('app/paste_html.html', user=user, url=raw_url, error="Please paste the full HTML source code (it seems too short).")

    stats = _get_user_stats(user["id"])
    limit = SCAN_LIMITS.get(stats["plan"], 1)
    user_email = (user.get("email") or "").lower()
    if user_email not in ADMIN_EMAILS:
        if stats["scans_this_month"] >= limit:
            return render_template('app/new.html', user=user, quota_exceeded=True)

    job_id = str(uuid.uuid4())
    AUDIT_JOBS[job_id] = {
        "status": "running",
        "result": None,
        "error": None,
        "url": url,
        "user_id": user["id"],
        "user_name": f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or user.get("email") or "Unknown"
    }
    thread = threading.Thread(target=run_audit_with_html, args=(job_id, url, pasted_html))
    thread.daemon = True
    thread.start()
    return render_template('app/processing.html', user=user, url=url, job_id=job_id)


@app.route('/app/results', methods=['GET', 'POST'])
def audit_results():
    user = session.get("user")
    if not user:
        return redirect('/login')
    refresh_subscription_status(user["id"])
    #if _rate_limited(f"audit_results:{_client_ip()}"):
    #    return redirect(url_for('index', error="Too many audits. Please wait a minute and try again."))

    stats = _get_user_stats(user["id"])
    limit = SCAN_LIMITS.get(stats["plan"], 1)
    user_email = (user.get("email") or "").lower() if user else ""
    if user_email not in ADMIN_EMAILS:
        if stats["scans_this_month"] >= limit:
            user_name_str = f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or user.get("email") or "Unknown"
            plan_label = stats.get("plan") or "free"
            limit_val = SCAN_LIMITS.get(plan_label, 1)
            _send_scan_webhook(
                status="blocked",
                reason=f"limit_reached: already used {stats['scans_this_month']}/{limit_val} scans ({plan_label} plan)",
                url=url,
                user_id=user.get("id"),
                plan=plan_label,
                user_name=user_name_str
            )
            return render_template('app/new.html', user=user, quota_exceeded=True)

    raw_url = request.values.get('url', '')
    url = normalize_url(raw_url)
    if not url:
        return redirect(url_for(
            'index',
            error="Please enter a valid URL (example: https://example.com)."
        ))

    # Prevent duplicate scans: if user already has a running job, redirect to it
    for existing_id, existing_job in AUDIT_JOBS.items():
        if existing_job.get("user_id") == user["id"] and existing_job["status"] == "running":
            return redirect(url_for("audit_status", job_id=existing_id))

    job_id = str(uuid.uuid4())

    AUDIT_JOBS[job_id] = {
        "status": "running",
        "result": None,
        "error": None,
        "url": url,
        "user_id": user["id"],
        "user_name": f'{user.get("first_name") or ""} {user.get("last_name") or ""}'.strip() or user.get("email") or "Unknown"
    }

    thread = threading.Thread(target=run_audit, args=(job_id, url))
    thread.daemon = True
    thread.start()

    return redirect(url_for("audit_status", job_id=job_id))

@app.route('/app/results/<job_id>')
def audit_status(job_id):
    job = AUDIT_JOBS.get(job_id)

    if not job:
        return render_template(
            "app/error.html",
            error="Audit not found. Please try again."
        )

    if job["status"] == "running":
        return render_template("app/processing.html", url=job.get("url"), job_id=job_id)

    if job["status"] == "blocked_page":
        return render_template(
            "app/paste_html.html",
            url=job.get("url"),
            user=session.get("user")
        )

    if job["status"] == "error":
        return render_template(
            "app/error.html",
            error=job["error"]
        )

    audit = job["result"]
    audit_json = json.dumps(audit, indent=2)
    user = session.get("user")
    limited_view = True
    if user:
        stats = _get_user_stats(user["id"])
        limited_view = stats.get("plan") != "paid"
    if (audit.get("metadata") or {}).get("upgrade_required") and limited_view:
        return render_template("app/error.html", error="This site is too large for the free plan. Upgrade to Pro to scan larger websites.", upgrade=True)
    if (audit.get("metadata") or {}).get("model_limit"):
        return render_template("app/error.html", error="This site is too large for the current model capacity. Please try a smaller page or check back later.")

    llm_prompt = generate_llm_prompt(audit)

    return render_template(
        "app/results.html",
        audit=audit,
        audit_json=audit_json,
        limited_view=limited_view,
        llm_prompt=llm_prompt,
        audit_id=job.get("audit_id")
    )


@app.route('/app/audits/<audit_id>')
def audit_detail(audit_id):
    user = session.get("user")
    if not user:
        return redirect('/login')
    try:
        resp = supabase.table("audits").select("id,url,result,created_at").eq("id", audit_id).eq("user_id", user["id"]).single().execute()
        audit_row = resp.data
    except Exception as e:
        print("Failed to load audit detail:", e)
        return render_template("app/error.html", error="Audit not found. Please try again.")

    audit = audit_row.get("result")
    audit["created_at"] = audit_row.get("created_at")
    audit_json = json.dumps(audit, indent=2)
    share_url = get_public_base_url() + "/share/" + audit_id
    stats = _get_user_stats(user["id"])
    limited_view = stats.get("plan") != "paid"
    if (audit.get("metadata") or {}).get("upgrade_required") and limited_view:
        return render_template("app/error.html", error="This site is too large for the free plan. Upgrade to Pro to scan larger websites.", upgrade=True)
    if (audit.get("metadata") or {}).get("model_limit"):
        return render_template("app/error.html", error="This site is too large for the current model capacity. Please try a smaller page or check back later.")
    llm_prompt = generate_llm_prompt(audit)
    return render_template("app/results.html", audit=audit, audit_json=audit_json, share_url=share_url, limited_view=limited_view, llm_prompt=llm_prompt, audit_id=audit_id)


@app.route('/share/<audit_id>')
def share_audit(audit_id):
    try:
        resp = supabase.table("audits").select("id,url,result,created_at").eq("id", audit_id).single().execute()
        audit_row = resp.data
    except Exception as e:
        print("Failed to load shared audit:", e)
        return render_template("app/error.html", error="Audit not found.")

    audit = audit_row.get("result")
    audit["created_at"] = audit_row.get("created_at")
    audit_json = json.dumps(audit, indent=2)
    share_url = get_public_base_url() + "/share/" + audit_id
    user = session.get("user")
    logged_out = user is None
    limited_view = True
    if user:
        stats = _get_user_stats(user["id"])
        limited_view = stats.get("plan") != "paid"
    if (audit.get("metadata") or {}).get("model_limit") and not (audit.get("metadata") or {}).get("upgrade_required"):
        return render_template("app/error.html", error="This site is too large for the current model capacity. Please try a smaller page or check back later.")
    if logged_out:
        audit = _sanitize_audit_for_public(audit)
        audit_json = json.dumps(audit, indent=2)
    llm_prompt = generate_llm_prompt(audit)
    return render_template(
        "app/results.html",
        audit=audit,
        audit_json=audit_json,
        share_url=share_url,
        limited_view=limited_view,
        force_blur=logged_out,
        require_login=logged_out,
        obfuscate=False,
        shared_audit_id=audit_id,
        llm_prompt=llm_prompt
    )


@app.route('/app/results/<job_id>/status')
def audit_status_api(job_id):
    job = AUDIT_JOBS.get(job_id)
    if not job:
        return jsonify({"status": "not_found"}), 404
    resp = {
        "status": job["status"],
        "error": job.get("error"),
        "audit_id": job.get("audit_id"),
        "fallback": job.get("fallback", False)
    }
    if job["status"] == "blocked_page":
        resp["blocked_url"] = job.get("url")
    return jsonify(resp)



@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1500)
