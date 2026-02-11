
import json
import os
import httpx
from openai import OpenAI
from datetime import datetime
import requests

EXAMPLE_AUDIT = {
    "scan_id": "scan_YYYYMMDD_random",
    "url": "https://example.com",
    "scanned_at": "ISO_8601_TIMESTAMP",
    "scan_duration_ms": 1234,
    "scores": {
        "overall": {"score": 0, "grade": "A-F", "summary": ""},
        "seo": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "conversion": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "performance": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "accessibility": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "security": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
    },
    "issues": {
        "total": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "items": [
            {
                "category": "performance",
                "severity": "high",
                "name": "Render-blocking resources",
                "description": "CSS/JS files block initial render and delay first paint.",
                "impact": "Slower perceived load time and higher bounce rate.",
                "solution": "Inline critical CSS and defer non-critical JS.",
                "code_example": "<link rel=\"preload\" as=\"style\" href=\"/styles.css\" onload=\"this.rel='stylesheet'\">",
                "affected_elements": [
                    {"location": "head", "selector": "link[href*='styles.css']"}
                ],
            }
        ],
    },
    "seo": {
        "summary": "",
        "elements": {
            "title_tag": {
                "status": "passed",
                "value": "Example Page Title",
                "length": 42,
                "why_important": "The title tag is a key ranking factor and affects click-through rate.",
                "recommendation": "",
                "suggested_value": "",
            },
            "meta_description": {
                "status": "warning",
                "value": "Short description",
                "length": 32,
                "why_important": "Meta descriptions influence CTR on search results pages.",
                "recommendation": "Expand the description to 120-160 characters.",
                "suggested_value": "A concise, benefit-driven summary of the page content.",
            },
            "alt_text_coverage": {
                "status": "failed",
                "images_with_alt": 2,
                "total_images": 5,
                "images_without_alt": 3,
                "why_important": "Alt text improves accessibility and image SEO.",
                "recommendation": "Add descriptive alt text to all decorative and functional images.",
                "suggested_value": "",
            },
        },
    },
    "conversion": {
        "summary": "",
        "cta_analysis": {
            "total_ctas": 0,
            "overall_effectiveness": "",
            "recommendations": [
                {
                    "location": "Hero section",
                    "original": {
                        "text": "Get Started",
                        "style_notes": "Generic CTA text",
                    },
                    "suggested": {
                        "text": "Start Your Free Audit",
                        "reasoning": "Clear benefit + low friction",
                        "expected_improvement": "+10-20% CTR",
                    },
                    "issues": ["Weak urgency", "Low specificity"],
                }
            ],
        },
        "copy_changes": [
            {
                "location": "Hero headline",
                "original_text": "All-in-one platform for teams",
                "suggested_text": "Turn more visitors into customers in 30 seconds",
                "reasoning": "Leads with outcome and time-to-value.",
                "expected_impact": "+6-14% conversion rate",
            },
            {
                "location": "Hero subheadline",
                "original_text": "Everything you need in one place",
                "suggested_text": "See exactly what's costing you signups and fix it fast.",
                "reasoning": "Clarifies pain + promise in one sentence.",
                "expected_impact": "+4-9% conversion rate",
            },
            {
                "location": "Primary CTA",
                "original_text": "Get Started",
                "suggested_text": "Audit my page for free",
                "reasoning": "Adds intent and reduces friction.",
                "expected_impact": "+5-10% CTR",
            },
            {
                "location": "How it works intro",
                "original_text": "Drop in any URL. We'll tell you exactly what's working.",
                "suggested_text": "Paste a URL and get a ranked list of fixes that increase signups.",
                "reasoning": "Makes outcome and format explicit.",
                "expected_impact": "+3-7% conversion rate",
            },
            {
                "location": "Features section headline",
                "original_text": "Everything You Need to Optimize",
                "suggested_text": "Fix the 5 issues that hurt conversions most",
                "reasoning": "Gives a concrete, prioritized benefit.",
                "expected_impact": "+3-6% CTR",
            },
            {
                "location": "Feature 1 description",
                "original_text": "Evaluate CTAs, headlines, form placement...",
                "suggested_text": "Get specific headline, CTA, and layout fixes you can apply today.",
                "reasoning": "Focuses on actionable outcomes.",
                "expected_impact": "+2-5% CTR",
            },
            {
                "location": "Social proof quote",
                "original_text": "\"PageAudit found 12 conversion issues...\"",
                "suggested_text": "\"We fixed 7 issues in a day and signups jumped 22%.\"",
                "reasoning": "Adds a clear, quantified result.",
                "expected_impact": "+2-4% conversion rate",
            },
            {
                "location": "Pricing CTA",
                "original_text": "Learn more",
                "suggested_text": "See plans & start free",
                "reasoning": "Adds intent and a low-friction next step.",
                "expected_impact": "+3-8% CTR",
            },
            {
                "location": "FAQ answer",
                "original_text": "Most audits complete in under 30 seconds.",
                "suggested_text": "Most audits finish in 30 seconds with a prioritized fix list.",
                "reasoning": "Reinforces speed + outcome.",
                "expected_impact": "+1-3% conversion rate",
            },
            {
                "location": "Footer CTA",
                "original_text": "Start Free Audit",
                "suggested_text": "Run my free audit now",
                "reasoning": "First-person framing increases intent.",
                "expected_impact": "+2-5% CTR",
            },
            {
                "location": "CTA helper text",
                "original_text": "Free to use. No card required.",
                "suggested_text": "Free audit in seconds. No credit card.",
                "reasoning": "Shorter and reduces friction.",
                "expected_impact": "+1-3% CTR",
            },
            {
                "location": "Feature section intro",
                "original_text": "A complete toolkit for landing page analysis.",
                "suggested_text": "A focused checklist that tells you what to fix first.",
                "reasoning": "Emphasizes prioritization.",
                "expected_impact": "+2-4% CTR",
            },
        ],
    },
    "performance": {
        "summary": "",
        "page_weight": {
            "total_kb": 0,
            "images_kb": 0,
            "js_kb": 0,
            "css_kb": 0,
            "fonts_kb": 0,
            "html_kb": 0,
        },
        "metrics": {
            "first_contentful_paint": {"value_ms": 0, "status": "good", "score": 100},
            "largest_contentful_paint": {"value_ms": 0, "status": "good", "score": 100},
            "total_blocking_time": {"value_ms": 0, "status": "good", "score": 100},
            "cumulative_layout_shift": {"value": 0, "status": "good", "score": 100},
            "speed_index": {"value_ms": 0, "status": "good", "score": 100},
        },
    },
    "accessibility": {
        "summary": "",
        "wcag_level": "AA",
        "compliance_percentage": 100,
        "keyboard_navigation": {"score": 100, "status": "passed", "issues": []},
        "screen_reader": {"score": 100, "status": "passed", "issues": []},
        "color_contrast": {"score": 100, "status": "passed", "issues": []},
    },
    "security": {
        "summary": "",
        "overall_risk": "low",
        "checks": {
            "csp_headers": {
                "status": "failed",
                "severity": "high",
                "description": "No Content Security Policy header detected.",
                "recommendation": "Add a strict CSP header to prevent XSS and data injection attacks.",
            },
            "xss_vectors": {
                "status": "warning",
                "severity": "medium",
                "description": "User input may be rendered without sanitization.",
                "recommendation": "Sanitize all user inputs and avoid innerHTML/dangerouslySetInnerHTML.",
            },
            "sensitive_data_exposure": {
                "status": "passed",
                "severity": "critical",
                "description": "No API keys, tokens, or environment variables found in source.",
                "recommendation": "",
            },
            "dependency_safety": {
                "status": "warning",
                "severity": "medium",
                "description": "CDN scripts loaded without Subresource Integrity (SRI) hashes.",
                "recommendation": "Add integrity and crossorigin attributes to all external scripts.",
            },
            "clickjacking_protection": {
                "status": "failed",
                "severity": "high",
                "description": "Page can be embedded in iframes. No X-Frame-Options or frame-ancestors CSP directive.",
                "recommendation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            },
            "insecure_storage": {
                "status": "warning",
                "severity": "medium",
                "description": "Auth tokens stored in localStorage instead of secure cookies.",
                "recommendation": "Use httpOnly, Secure, SameSite cookies for authentication tokens.",
            },
            "form_security": {
                "status": "passed",
                "severity": "low",
                "description": "Forms have proper validation and autocomplete attributes.",
                "recommendation": "",
            },
            "open_redirects": {
                "status": "passed",
                "severity": "high",
                "description": "No open redirect vectors found in client-side routing.",
                "recommendation": "",
            },
            "mixed_content": {
                "status": "passed",
                "severity": "medium",
                "description": "All assets loaded over HTTPS.",
                "recommendation": "",
            },
            "debug_artifacts": {
                "status": "warning",
                "severity": "low",
                "description": "Console.log statements and source maps detected in production.",
                "recommendation": "Remove debug statements and disable source maps for production builds.",
            },
        },
        "vulnerabilities": [
            {
                "type": "xss",
                "severity": "high",
                "location": "Search input field",
                "description": "URL parameters injected into DOM without sanitization.",
                "proof": "?q=<script>alert(1)</script> renders in page",
                "fix": "Use textContent instead of innerHTML, sanitize all query params.",
            }
        ],
    },
    "metadata": {
        "scanner_version": "2.1.0",
        "page_type": "",
        "technology_stack": {
            "framework": "",
            "analytics": [],
        },
    },
}

EXAMPLE_JSON = json.dumps(EXAMPLE_AUDIT, indent=2)
DEFAULT_AUDIT = json.loads(EXAMPLE_JSON)


def _merge_schema(base, data):
    if isinstance(base, dict):
        result = {}
        source = data if isinstance(data, dict) else {}
        for key, value in base.items():
            if key in source:
                result[key] = _merge_schema(value, source.get(key))
            else:
                result[key] = value
        return result
    if isinstance(base, list):
        return data if isinstance(data, list) else base
    return base if data is None else data


def _extract_json(text: str) -> str:
    content = (text or "").strip()
    if "```" in content:
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            return content[start:end + 1]
    return content

def scrape(url: str) -> str:
    import cloudscraper
    import time

    scraper = cloudscraper.create_scraper(
        browser={"browser": "chrome", "platform": "windows", "desktop": True}
    )

    max_retries = 3
    for attempt in range(max_retries):
        response = scraper.get(url, timeout=20)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 2 ** (attempt + 1)))
            time.sleep(retry_after)
            continue
        response.raise_for_status()
        return response.text

    raise Exception(f"Failed to fetch {url} after {max_retries} retries (429 Too Many Requests)")


def _is_placeholder_result(data: dict) -> bool:
    """Detect when the model returned the example schema instead of real data."""
    if not isinstance(data, dict):
        return True
    scores = data.get("scores")
    if isinstance(scores, dict):
        overall = scores.get("overall")
        if isinstance(overall, dict):
            grade = overall.get("grade")
            if grade == "A-F":
                return True
            if overall.get("score") == 0 and overall.get("summary") == "":
                seo = scores.get("seo", {})
                perf = scores.get("performance", {})
                if seo.get("score") == 0 and perf.get("score") == 0:
                    return True
    return False


def _run_model_new(client, model: str, prompt: str, max_retries: int = 2) -> dict:
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            extracted = _extract_json(content)
            parsed = json.loads(extracted)
            if isinstance(parsed, str):
                parsed = {}

            if _is_placeholder_result(parsed):
                print(f"Model returned placeholder/template data (attempt {attempt + 1}), retrying...")
                last_err = ValueError("Model returned placeholder data instead of real analysis")
                continue

            return parsed
        except json.JSONDecodeError as e:
            print(f"JSON parse error (attempt {attempt + 1}): {e}")
            last_err = e
            continue
        except Exception as e:
            print(f"Model call error (attempt {attempt + 1}): {e}")
            last_err = e
            continue

    raise last_err or ValueError("Failed to get valid audit from model")



def _build_audit_prompt(html: str, url: str, current_date: str) -> str:
    return f"""
You are an advanced website auditing engine.
Today's date is: {current_date}

Analyze the HTML source of this website:
URL: {url}

You MUST return a JSON object that MATCHES the STRUCTURE and DEPTH of the example below.
Fill it with realistic scores, issues, explanations, and recommendations.

RULES:
- Output ONLY valid JSON
- Fill EVERYTHING in the json with REAL data from the HTML analysis
- NEVER copy the example values verbatim — every value must reflect the actual page
- The grade field must be a single letter (A, B, C, D, or F) — NEVER output "A-F"
- All scores must be real numbers (0-100) based on your analysis — NEVER leave them as 0 unless truly warranted
- No markdown
- No commentary
- No extra keys
- Match the nesting and intent of the example
- Populate every field with realistic values (avoid empty strings/arrays unless truly no data).
- If a list can have items, include at least 3 items.
- Ensure conversion.copy_changes has 10+ entries.
- Ensure issues.items has 8+ entries spanning all categories and severities.
- Ensure issues.total and severity counts match issues.items.
- Never mention AI or "AI-powered" in any copy suggestions; be informative and conversion-focused.
- Make copy_changes cover most of the page: hero, subheadline, primary CTA, features, paragraphs, social proof, pricing, FAQ, footer, and more.
- Don't fill ANYTHING randomly
- Be brutally honest
- Never use em dashes on copy suggestions
- Make copy_changes cover bigger parts of text as well (paragraphs) not only headlines, and make sure there are many suggestions for different parts of the website to increase conversion.
- Ensure security checks cover: CSP headers, XSS vectors, sensitive data exposure, dependency/script safety (SRI), clickjacking protection, insecure storage, form security, open redirects, mixed content, and debug artifacts.
- Include security issues in the issues.items array with category "security".
- Be thorough about security: check for exposed API keys, tokens, env variables in HTML source, inline scripts with dynamic values, missing integrity attributes on CDN scripts, localStorage usage for auth, console.log in production, source maps, and open redirect vectors.

EXAMPLE JSON (schema reference):
{EXAMPLE_JSON}

HTML SOURCE:
----------------
{html}
----------------
"""


def analyze_with_ai(html: str, url: str) -> dict:
    api_key = os.environ.get("OPENAI_KEY")
    client = OpenAI(api_key=api_key, http_client=httpx.Client())
    current_date = datetime.utcnow().date().isoformat()
    prompt = _build_audit_prompt(html, url, current_date)
    parsed = _run_model_new(client, "gpt-4o-mini", prompt)
    audit = _merge_schema(DEFAULT_AUDIT, parsed)
    audit["url"] = url
    if not audit.get("scanned_at"):
        audit["scanned_at"] = datetime.utcnow().isoformat()
    return audit




def analyze(url, plan="free", on_fallback=None):
    import time
    start_time = time.monotonic()
    html_code = scrape(url)

    def _with_duration(audit):
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        audit["scan_duration_ms"] = elapsed_ms
        return audit

    try:
        audit = analyze_with_ai(html_code, url)
        audit["_scan_cost"] = 1
        return _with_duration(audit)
    except Exception as e:
        print("gpt-4o-mini failed:", e)

    if plan != "paid":
        audit = _merge_schema(DEFAULT_AUDIT, {})
        audit["url"] = url
        audit["scanned_at"] = datetime.utcnow().isoformat()
        audit["scores"]["overall"]["summary"] = "This site is too large for the free plan. Upgrade to Pro to scan larger sites."
        audit["metadata"]["model_limit"] = True
        audit["metadata"]["upgrade_required"] = True
        audit["issues"]["items"] = []
        audit["issues"]["total"] = 0
        audit["_scan_cost"] = 0
        return _with_duration(audit)

    if on_fallback:
        on_fallback()

    try:
        api_key = os.environ.get("OPENAI_KEY")
        client = OpenAI(api_key=api_key, http_client=httpx.Client())
        current_date = datetime.utcnow().date().isoformat()
        prompt = _build_audit_prompt(html_code, url, current_date)
        parsed = _run_model_new(client, "gpt-4.1-mini", prompt)
        audit = _merge_schema(DEFAULT_AUDIT, parsed)
        audit["url"] = url
        if not audit.get("scanned_at"):
            audit["scanned_at"] = datetime.utcnow().isoformat()
        audit["_scan_cost"] = 1
        return _with_duration(audit)
    except Exception as e:
        print("gpt-4.1-mini failed:", e)

    audit = _merge_schema(DEFAULT_AUDIT, {})
    audit["url"] = url
    audit["scanned_at"] = datetime.utcnow().isoformat()
    audit["scores"]["overall"]["summary"] = "We were unable to process this website. The maximum model limit was reached. Please contact support."
    audit["metadata"]["model_limit"] = True
    audit["issues"]["items"] = []
    audit["issues"]["total"] = 0
    audit["_scan_cost"] = 0
    return _with_duration(audit)
