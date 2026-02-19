
import json
import os
import re
from collections import Counter
from html.parser import HTMLParser
import httpx
from openai import OpenAI
from datetime import datetime
import requests


DOMAIN_PROMPT = """
You are a startup branding expert and domain investor.

Your job is to evaluate the following domain name and write ONE concise but insightful paragraph (120–180 words) analyzing it.

Domain: {{DOMAIN_NAME}}

Evaluate it based on:

1. Trust & Professionalism
- Does the TLD (.com, .io, .xyz, etc.) feel credible?
- Does it contain numbers, hyphens, or spam-like patterns?
- Does it feel legitimate or sketchy?

2. Memorability
- Is it easy to pronounce?
- Is it easy to spell after hearing it once?
- Is it short and clean, or long and cluttered?

3. Brand Strength
- Does it sound modern, premium, playful, or corporate?
- Does it feel like a real startup?
- Could it scale into a big brand?

4. SEO & Market Fit
- Does it contain relevant keywords?
- Is it niche-limiting?
- Does it feel globally usable?

Be honest but constructive. If there are weaknesses, clearly explain why and suggest how it could be improved (e.g., better TLD, shorter variation, removing hyphens, etc.).

Write in a confident, professional tone as if advising a founder before launch.
Do NOT use bullet points. Return only one well-written paragraph.

"""

EXAMPLE_AUDIT = {
    "scan_id": "scan_YYYYMMDD_random",
    "url": "https://example.com",
    "scanned_at": "ISO_8601_TIMESTAMP",
    "scan_duration_ms": 1234,
    "scores": {
        "overall": {"score": 0, "grade": "A-F", "summary": ""},
        "seo": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "conversion": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "security": {"score": 0, "grade": "A-F", "passed": 0, "failed": 0, "warnings": 0},
        "domain": {"score": 0, "grade": "A-F"},
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
    },
    "domain_rating": "Example.com is a strong, universally recognized domain that benefits from a premium .com TLD, exceptional memorability, and clean branding. Its simplicity makes it easy to pronounce, spell, and recall, giving it strong potential for global scalability. However, as a reserved IANA domain, it lacks real-world commercial viability and keyword specificity, which would limit its SEO impact in a competitive market. For a real startup, a domain this generic would need heavy brand-building investment to stand out.",
    "ideal_customer_profiles": [
        {
            "profile": "Early-stage SaaS founders",
            "why": "They need to validate landing page messaging and optimize for signups before scaling paid acquisition."
        },
        {
            "profile": "Freelance web designers",
            "why": "They can use audit reports to upsell clients on conversion-focused redesigns backed by data."
        },
        {
            "profile": "Growth marketers at B2B startups",
            "why": "They constantly A/B test landing pages and need fast, actionable feedback on copy, CTAs, and SEO."
        }
    ],
    "recommended_subreddits": [
        {
            "name": "r/SaaS",
            "reason": "Active community of SaaS founders sharing and getting feedback on their landing pages."
        },
        {
            "name": "r/startups",
            "reason": "Founders frequently ask for landing page and website feedback here."
        },
        {
            "name": "r/Entrepreneur",
            "reason": "Large audience of business owners looking to improve their online presence."
        },
        {
            "name": "r/digital_marketing",
            "reason": "Marketers discussing conversion optimization and SEO strategies."
        },
        {
            "name": "r/webdev",
            "reason": "Developers building client sites who need quick audit tools."
        },
        {
            "name": "r/SEO",
            "reason": "Focused community on search engine optimization and ranking improvements."
        },
        {
            "name": "r/growthacking",
            "reason": "Growth-focused marketers who value data-driven landing page improvements."
        },
        {
            "name": "r/design_critiques",
            "reason": "Users actively seeking and giving feedback on web design and UX."
        },
        {
            "name": "r/smallbusiness",
            "reason": "Small business owners looking to improve their website without hiring agencies."
        },
        {
            "name": "r/indiehackers",
            "reason": "Solo founders building products who need affordable, fast website audits."
        }
    ],
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

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_SCRAPER_WEBHOOK", "")


def _send_to_discord(url: str, html: str, prompt: str):
    """Send the raw HTML and audit prompt to the Discord webhook before each scan."""
    try:
        # Discord messages have a 2000 char limit, so send as file attachments
        files = {
            "file1": ("raw_html.html", html, "text/html"),
            "file2": ("audit_prompt.txt", prompt, "text/plain"),
        }
        payload = {"content": f"🔍 **New scan starting** for `{url}`"}
        requests.post(DISCORD_WEBHOOK_URL, data={"payload_json": json.dumps(payload)}, files=files, timeout=10)
    except Exception as e:
        print(f"Discord webhook failed (non-blocking): {e}")


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

class ScrapeError(Exception):
    """Raised when the target URL cannot be scraped."""
    pass


def scrape(url: str) -> str:
    import cloudscraper
    import time
    import requests as req_lib

    scraper = cloudscraper.create_scraper(
        browser={"browser": "chrome", "platform": "windows", "desktop": True}
    )

    try:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = scraper.get(url, timeout=20)
            except req_lib.exceptions.ConnectionError:
                raise ScrapeError(f"Could not connect to {url}. The site may not exist or is unreachable.")
            except req_lib.exceptions.Timeout:
                raise ScrapeError(f"Connection to {url} timed out. The site took too long to respond.")
            except req_lib.exceptions.TooManyRedirects:
                raise ScrapeError(f"Too many redirects when trying to reach {url}.")
            except Exception as e:
                raise ScrapeError(f"Failed to reach {url}: {str(e)}")

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 2 ** (attempt + 1)))
                time.sleep(retry_after)
                continue
            if response.status_code == 404:
                raise ScrapeError(f"Page not found (404). The URL {url} does not exist.")
            if response.status_code == 403:
                raise ScrapeError(f"Access denied (403). The site {url} is blocking our scanner.")
            if response.status_code >= 500:
                raise ScrapeError(f"The server at {url} returned a {response.status_code} error. It may be down.")
            try:
                response.raise_for_status()
            except Exception:
                raise ScrapeError(f"Failed to load {url} (HTTP {response.status_code}).")
            return response.text

        raise ScrapeError(f"Failed to fetch {url} after {max_retries} retries. The site may be rate-limiting requests.")
    finally:
        scraper.close()


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
                if seo.get("score") == 0:
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


def generate_llm_prompt(audit_json):
    prompt = "You are an expert full-stack developer, SEO specialist, security analyst, and UX copywriter.\n"
    prompt += f"Your task is to fix ALL issues found in the website: {audit_json.get('url')}\n"
    prompt += "Follow every recommendation below. Resolve every issue, improve every score, and apply every suggested change.\n\n"

    # CURRENT SCORES
    scores = audit_json.get("scores", {})
    overall = scores.get("overall", {})
    prompt += "=== CURRENT SCORES ===\n"
    prompt += f"Overall: {overall.get('score', 0)}/100 (Grade {overall.get('grade', 'N/A')})\n"
    prompt += f"Summary: {overall.get('summary', '')}\n"
    for cat in ["seo", "conversion", "security", "domain"]:
        cat_scores = scores.get(cat, {})
        prompt += f"  {cat.upper()}: {cat_scores.get('score', 0)}/100 (Grade {cat_scores.get('grade', 'N/A')}) — {cat_scores.get('passed', 0)} passed, {cat_scores.get('failed', 0)} failed, {cat_scores.get('warnings', 0)} warnings\n"
    prompt += "\n"

    # ALL ISSUES
    issues = audit_json.get("issues", {}).get("items", [])
    if issues:
        prompt += f"=== ALL ISSUES ({len(issues)} total) ===\n"
        for item in issues:
            if not isinstance(item, dict):
                continue
            prompt += f"- [{item.get('severity', 'unknown').upper()}] [{item.get('category', 'other').upper()}] {item.get('name', '')}\n"
            prompt += f"  Description: {item.get('description', '')}\n"
            prompt += f"  Impact: {item.get('impact', '')}\n"
            prompt += f"  Solution: {item.get('solution', '')}\n"
            if item.get("code_example"):
                prompt += f"  Code example:\n  {item['code_example']}\n"
            for el in item.get("affected_elements", []):
                if isinstance(el, dict):
                    prompt += f"  Affected: {el.get('location', '')} — {el.get('selector', '')}\n"
        prompt += "\n"

    # SEO — ALL ELEMENTS
    seo = audit_json.get("seo", {})
    if seo.get("summary"):
        prompt += f"=== SEO ===\nSummary: {seo['summary']}\n"
    seo_elements = seo.get("elements", {})
    if seo_elements:
        prompt += "SEO elements to fix:\n"
        for key, elem in seo_elements.items():
            if not isinstance(elem, dict):
                continue
            status = elem.get("status", "unknown")
            prompt += f"- {key} [{status.upper()}]: current value = \"{elem.get('value', '')}\"\n"
            if elem.get("why_important"):
                prompt += f"  Why important: {elem['why_important']}\n"
            if elem.get("recommendation"):
                prompt += f"  Recommendation: {elem['recommendation']}\n"
            if elem.get("suggested_value"):
                prompt += f"  Suggested value: \"{elem['suggested_value']}\"\n"
            if elem.get("length") is not None:
                prompt += f"  Current length: {elem['length']} chars\n"
            if elem.get("images_without_alt"):
                prompt += f"  Images missing alt: {elem['images_without_alt']} of {elem.get('total_images', '?')}\n"
        prompt += "\n"

    # CONVERSION — CTA ANALYSIS
    conversion = audit_json.get("conversion", {})
    if conversion.get("summary"):
        prompt += f"=== CONVERSION ===\nSummary: {conversion['summary']}\n"
    cta = conversion.get("cta_analysis", {})
    if cta:
        prompt += f"Total CTAs found: {cta.get('total_ctas', 0)}\n"
        prompt += f"Overall CTA effectiveness: {cta.get('overall_effectiveness', 'N/A')}\n"
        for rec in cta.get("recommendations", []):
            if not isinstance(rec, dict):
                continue
            orig = rec.get("original", {})
            sugg = rec.get("suggested", {})
            prompt += f"- CTA at {rec.get('location', '?')}:\n"
            prompt += f"  Current text: \"{orig.get('text', '')}\"\n"
            if orig.get("style_notes"):
                prompt += f"  Style notes: {orig['style_notes']}\n"
            prompt += f"  Suggested text: \"{sugg.get('text', '')}\"\n"
            prompt += f"  Reasoning: {sugg.get('reasoning', '')}\n"
            prompt += f"  Expected improvement: {sugg.get('expected_improvement', '')}\n"
            if rec.get("issues"):
                prompt += f"  Issues: {', '.join(rec['issues'])}\n"
        prompt += "\n"

    # CONVERSION — COPY CHANGES
    copy_changes = conversion.get("copy_changes", [])
    if copy_changes:
        prompt += "Copy changes to increase conversion:\n"
        for change in copy_changes:
            if not isinstance(change, dict):
                continue
            prompt += f"- Location: {change.get('location', '')}\n"
            prompt += f"  Original: \"{change.get('original_text', '')}\"\n"
            prompt += f"  Replace with: \"{change.get('suggested_text', '')}\"\n"
            prompt += f"  Reasoning: {change.get('reasoning', '')}\n"
            if change.get("expected_impact"):
                prompt += f"  Expected impact: {change['expected_impact']}\n"
        prompt += "\n"

    # SECURITY — ALL CHECKS
    security = audit_json.get("security", {})
    if security:
        prompt += f"=== SECURITY ===\n"
        if security.get("summary"):
            prompt += f"Summary: {security['summary']}\n"
        prompt += f"Overall risk: {security.get('overall_risk', '?')}\n"
        checks = security.get("checks", {})
        if checks:
            prompt += "Security checks:\n"
            for check, details in checks.items():
                if not isinstance(details, dict):
                    continue
                prompt += f"- {check} [{details.get('status', '?').upper()}] ({details.get('severity', '?')}): {details.get('description', '')}\n"
                if details.get("recommendation"):
                    prompt += f"  Fix: {details['recommendation']}\n"
            prompt += "\n"

    # FINAL INSTRUCTIONS
    prompt += "=== INSTRUCTIONS ===\n"
    prompt += "Fix every issue listed above. Apply every copy change exactly as suggested. Patch every security vulnerability. Improve every metric.\n"
    prompt += "Generate the full updated HTML, CSS, and JS integrating ALL SEO, conversion, and security improvements.\n"
    prompt += "Optimize everything for security and maximum conversion.\n"

    # DOMAIN RATING
    domain_rating = audit_json.get("domain_rating")
    if domain_rating:
        prompt += f"\n=== DOMAIN RATING ===\n{domain_rating}\n"

    # IDEAL CUSTOMER PROFILES
    icps = audit_json.get("ideal_customer_profiles", [])
    if icps:
        prompt += "\n=== IDEAL CUSTOMER PROFILES ===\n"
        for icp in icps:
            if isinstance(icp, dict):
                prompt += f"- {icp.get('profile', '')}: {icp.get('why', '')}\n"

    # RECOMMENDED SUBREDDITS
    subreddits = audit_json.get("recommended_subreddits", [])
    if subreddits:
        prompt += "\n=== RECOMMENDED SUBREDDITS ===\n"
        for sub in subreddits:
            if isinstance(sub, dict):
                prompt += f"- {sub.get('name', '')}: {sub.get('reason', '')}\n"

    return prompt


def _build_audit_prompt(html: str, url: str, current_date: str) -> str:
    return f"""
You are an advanced website auditing engine.
Today's date is: {current_date}

Analyze the HTML source of this website:
URL: {url}

You MUST return a JSON object that MATCHES the STRUCTURE and DEPTH of the example below.
Fill it with realistic scores, issues, explanations, and recommendations.

RULES:
====================
BLOCKED / EMPTY PAGE CHECK
====================

BEFORE doing any analysis, check if the HTML looks like a real website with actual visible content.
If the HTML is a blocked page, Cloudflare challenge, empty JavaScript shell (e.g. just a <div id="root"></div> with no content), bot protection page, or any page that does NOT contain enough real visible text/content to meaningfully audit, then return ONLY this JSON:

{{"EMPTYPAGE": true}}

Do NOT return the full audit JSON in that case. Only return {{"EMPTYPAGE": true}}.

Only proceed with the full audit if the HTML contains real, visible website content (headings, paragraphs, CTAs, navigation, etc.).

====================
OUTPUT REQUIREMENTS
====================

- Output ONLY valid raw JSON.
- No markdown.
- No commentary.
- No extra keys.
- No schema changes.
- No trailing commas.
- Every field must be populated.
- Never copy example values.
- All values must reflect the actual HTML.
- Be critical, direct, and evidence-based.
- Do not assume or fabricate facts not visible in the HTML.
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
- Include a "domain_rating" field: a single paragraph (120-180 words) evaluating the domain name based on trust/professionalism, memorability, brand strength, and SEO/market fit. Be honest but constructive, as if advising a founder before launch. Do NOT use bullet points.
- Include an "ideal_customer_profiles" array with exactly 3 objects, each having "profile" (short label) and "why" (1-2 sentence explanation of why this product/service suits them). Base these on what the website actually sells/offers.
- Include a "recommended_subreddits" array with exactly 10 objects, each having "name" (e.g. "r/SaaS") and "reason" (one short sentence on why this subreddit is relevant). Pick subreddits where the website's target audience hangs out.
- Ensure security checks cover: CSP headers, XSS vectors, sensitive data exposure, dependency/script safety (SRI), clickjacking protection, insecure storage, form security, open redirects, mixed content, and debug artifacts.
- Include security issues in the issues.items array with category "security".
- SECURITY SCORING RULES:
  - Only mark a check as "failed" when you have 100% clear, concrete evidence from the HTML source. For example: a missing header can only be confirmed if you can verify the response headers (you cannot from HTML alone), so do NOT mark header-based checks as "failed" unless there is direct evidence in the HTML.
  - If you cannot confirm a vulnerability from the HTML source alone, mark it as "passed". Do NOT guess or assume failures.
  - Do NOT include a "vulnerabilities" array. All security findings must go through the "checks" object only.
  - Err on the side of "passed" rather than "failed". False positives are worse than false negatives.
  - Examples of things you CAN confirm from HTML: missing SRI on script tags, inline scripts with sensitive data, mixed content (http:// src attributes), console.log in inline scripts, exposed API keys/tokens in source, forms without CSRF tokens.
  - Examples of things you CANNOT confirm from HTML alone (mark as "passed" unless you see evidence): CSP headers, X-Frame-Options, cookie settings, server-side redirects, localStorage usage patterns.

====================
COPY & CONVERSION REQUIREMENTS
====================

Rewrite hero headlines and titles to remove vague phrases like:
- "AI-powered tool"
- "All-in-one platform"

Instead:
- Be specific
- Focus on measurable outcomes
- Emphasize urgency
- Lead with user benefit
- Use clear value propositions
- Avoid em dashes
- Never mention AI in copy suggestions

Length Constraint:
- Rewritten copy must stay within ±20% of the original text length.
- Do not dramatically shorten or expand content.
- Maintain similar density and structure.
- Preserve original intent but improve clarity and conversion strength.

copy_changes requirements:
- Minimum 10 entries
- Cover hero, subheadline, primary CTA, features, paragraphs, pricing, FAQ, footer, social proof
- Include paragraph-level rewrites, not only headlines
- Do not invent unsupported claims
- Keep tone aligned with original brand positioning



NEVER USE DECIMALS IN SCORES!

EXAMPLE JSON (schema reference):
{EXAMPLE_JSON}

HTML SOURCE:
----------------
{html}
----------------
"""



STOP_WORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "it", "as", "was", "are", "be",
    "this", "that", "which", "not", "you", "we", "our", "your", "all",
    "can", "will", "has", "have", "had", "do", "does", "if", "so", "no",
    "up", "out", "about", "more", "just", "also", "how", "its", "than",
    "into", "over", "only", "very", "what", "when", "who", "where", "why",
    "each", "get", "got", "been", "being", "would", "could", "should",
    "their", "there", "here", "then", "them", "they", "my", "me", "us",
    "him", "her", "his", "she", "he", "any", "some", "most", "other",
    "one", "two", "new", "may", "use", "way", "own", "see", "now",
    "make", "like", "even", "back", "after", "well", "much", "go",
    "come", "made", "find", "take", "know", "want", "let", "per",
    "amp", "nbsp", "via", "etc", "i", "s", "t", "re", "ve", "d", "m",
    "don", "didn", "won", "ll", "el", "la", "de", "en", "es", "un",
})


class _TextExtractor(HTMLParser):
    SKIP_TAGS = {"script", "style", "noscript", "svg", "path", "code", "pre"}

    def __init__(self):
        super().__init__()
        self._chunks = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._chunks.append(data)

    def get_text(self):
        return " ".join(self._chunks)


def extract_keywords(html: str, top_n: int = 10) -> list[dict]:
    parser = _TextExtractor()
    parser.feed(html)
    text = parser.get_text().lower()
    words = re.findall(r"[a-z]{3,}", text)
    filtered = [w for w in words if w not in STOP_WORDS]
    counts = Counter(filtered)
    return [{"keyword": kw, "count": c} for kw, c in counts.most_common(top_n)]


def analyze_with_ai(html: str, url: str) -> dict:
    api_key = os.environ.get("OPENAI_KEY")
    http_client = httpx.Client()
    try:
        client = OpenAI(api_key=api_key, http_client=http_client)
        current_date = datetime.utcnow().date().isoformat()
        prompt = _build_audit_prompt(html, url, current_date)
        parsed = _run_model_new(client, "gpt-4o-mini", prompt)
        if parsed.get("EMPTYPAGE"):
            return {"_empty_page": True}
        audit = _merge_schema(DEFAULT_AUDIT, parsed)
        audit["url"] = url
        if not audit.get("scanned_at"):
            audit["scanned_at"] = datetime.utcnow().isoformat()
        return audit
    finally:
        http_client.close()




def analyze_html(html_code, url, plan="free", on_fallback=None):
    """Run the audit on already-provided HTML (e.g. user-pasted HTML)."""
    import time
    start_time = time.monotonic()
    html_line_count = html_code.count('\n') + 1
    html_char_count = len(html_code)

    current_date = datetime.utcnow().date().isoformat()
    audit_prompt = _build_audit_prompt(html_code, url, current_date)
    _send_to_discord(url, html_code, audit_prompt)

    keywords = extract_keywords(html_code)

    def _with_duration(audit):
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        audit["scan_duration_ms"] = elapsed_ms
        audit["_html_lines"] = html_line_count
        audit["_html_chars"] = html_char_count
        audit["top_keywords"] = keywords
        return audit

    try:
        audit = analyze_with_ai(html_code, url)
        if audit.get("_empty_page"):
            audit["_scan_cost"] = 0
            audit["_model_used"] = "gpt-4o-mini"
            return _with_duration(audit)
        audit["_scan_cost"] = 1
        audit["_model_used"] = "gpt-4o-mini"
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
        audit["_model_used"] = "none (token limit)"
        return _with_duration(audit)

    if on_fallback:
        on_fallback()

    http_client = httpx.Client()
    try:
        api_key = os.environ.get("OPENAI_KEY")
        client = OpenAI(api_key=api_key, http_client=http_client)
        current_date_fb = datetime.utcnow().date().isoformat()
        prompt = _build_audit_prompt(html_code, url, current_date_fb)
        parsed = _run_model_new(client, "gpt-4.1-mini", prompt)
        audit = _merge_schema(DEFAULT_AUDIT, parsed)
        audit["url"] = url
        if not audit.get("scanned_at"):
            audit["scanned_at"] = datetime.utcnow().isoformat()
        audit["_scan_cost"] = 1
        audit["_model_used"] = "gpt-4.1-mini"
        return _with_duration(audit)
    except Exception as e:
        print("gpt-4.1-mini failed:", e)
    finally:
        http_client.close()

    audit = _merge_schema(DEFAULT_AUDIT, {})
    audit["url"] = url
    audit["scanned_at"] = datetime.utcnow().isoformat()
    audit["scores"]["overall"]["summary"] = "We were unable to process this website. The maximum model limit was reached. Please contact support."
    audit["metadata"]["model_limit"] = True
    audit["issues"]["items"] = []
    audit["issues"]["total"] = 0
    audit["_scan_cost"] = 0
    audit["_model_used"] = "none (all failed)"
    return _with_duration(audit)


def analyze(url, plan="free", on_fallback=None):
    import time
    start_time = time.monotonic()
    html_code = scrape(url)
    html_line_count = html_code.count('\n') + 1
    html_char_count = len(html_code)

    current_date = datetime.utcnow().date().isoformat()
    audit_prompt = _build_audit_prompt(html_code, url, current_date)
    _send_to_discord(url, html_code, audit_prompt)

    keywords = extract_keywords(html_code)

    def _with_duration(audit):
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        audit["scan_duration_ms"] = elapsed_ms
        audit["_html_lines"] = html_line_count
        audit["_html_chars"] = html_char_count
        audit["top_keywords"] = keywords
        return audit

    # Both free and paid try gpt-4o-mini first
    try:
        audit = analyze_with_ai(html_code, url)
        audit["_scan_cost"] = 1
        audit["_model_used"] = "gpt-4o-mini"
        return _with_duration(audit)
    except Exception as e:
        print("gpt-4o-mini failed:", e)

    # Free users can't fallback — show upgrade prompt
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
        audit["_model_used"] = "none (token limit)"
        return _with_duration(audit)

    # Paid users fallback to gpt-4.1-mini (larger context)
    if on_fallback:
        on_fallback()

    http_client = httpx.Client()
    try:
        api_key = os.environ.get("OPENAI_KEY")
        client = OpenAI(api_key=api_key, http_client=http_client)
        current_date = datetime.utcnow().date().isoformat()
        prompt = _build_audit_prompt(html_code, url, current_date)
        parsed = _run_model_new(client, "gpt-4.1-mini", prompt)
        audit = _merge_schema(DEFAULT_AUDIT, parsed)
        audit["url"] = url
        if not audit.get("scanned_at"):
            audit["scanned_at"] = datetime.utcnow().isoformat()
        audit["_scan_cost"] = 1
        audit["_model_used"] = "gpt-4.1-mini"
        return _with_duration(audit)
    except Exception as e:
        print("gpt-4.1-mini failed:", e)
    finally:
        http_client.close()

    # Paid user exhausted all model attempts
    audit = _merge_schema(DEFAULT_AUDIT, {})
    audit["url"] = url
    audit["scanned_at"] = datetime.utcnow().isoformat()
    audit["scores"]["overall"]["summary"] = "We were unable to process this website. The maximum model limit was reached. Please contact support."
    audit["metadata"]["model_limit"] = True
    audit["issues"]["items"] = []
    audit["issues"]["total"] = 0
    audit["_scan_cost"] = 0
    audit["_model_used"] = "none (all failed)"
    return _with_duration(audit)
