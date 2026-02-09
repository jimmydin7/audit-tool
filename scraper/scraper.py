
import json
import os
import httpx
from openai import OpenAI
from openrouter import OpenRouter
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


def _run_model_new(client, model: str, prompt: str) -> dict:
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You output strict JSON only."},
            {"role": "user", "content": prompt},
        ],
    )

    content = response.choices[0].message.content
    extracted = _extract_json(content)
    try:
        parsed = json.loads(extracted)
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, str):
        parsed = {}
    return parsed


def _run_openrouter(prompt: str) -> dict:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENROUTER_API_KEY")
    client = OpenRouter(api_key=api_key, server_url="https://openrouter.ai/api/v1")
    response = client.chat.send(
        model="openai/gpt-oss-120b",
        messages=[
            {"role": "system", "content": "You output strict JSON only."},
            {"role": "user", "content": prompt},
        ],
    )
    content = response.choices[0].message.content
    extracted = _extract_json(content)
    try:
        parsed = json.loads(extracted)
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, str):
        parsed = {}
    return parsed


def analyze_with_ai(html: str, url: str, model: str = "gpt-4o-mini") -> dict:
    api_key = os.environ.get("OPENAI_KEY")
    client = OpenAI(api_key=api_key, http_client=httpx.Client())
    current_date = datetime.utcnow().date().isoformat()

    prompt = f"""
You are an advanced website auditing engine.
Today's date is: {current_date}

Analyze the HTML source of this website:
URL: {url}

You MUST return a JSON object that MATCHES the STRUCTURE and DEPTH of the example below.
Fill it with realistic scores, issues, explanations, and recommendations.

RULES:
- Output ONLY valid JSON
- Fill EVERYTHING in the json
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

EXAMPLE JSON (schema reference):
{EXAMPLE_JSON}

HTML SOURCE:
----------------
{html}
----------------
"""

    try:
        parsed = _run_openrouter(prompt)
    except Exception as e:
        print(f"OpenRouter failed, falling back to {model}:", e)
        parsed = _run_model_new(client, model, prompt)
    audit = _merge_schema(DEFAULT_AUDIT, parsed)
    audit["url"] = url
    if not audit.get("scanned_at"):
        audit["scanned_at"] = datetime.utcnow().isoformat()
    return audit




def analyze(url, plan="free", on_fallback=None):
    html_code = scrape(url)

    try:
        audit = analyze_with_ai(html_code, url, model="gpt-4o-mini")
        audit["_scan_cost"] = 1
        return audit
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
        return audit

    if on_fallback:
        on_fallback()

    try:
        audit = analyze_with_ai(html_code, url, model="gpt-4.1-mini")
        audit["_scan_cost"] = 1
        return audit
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
    return audit
