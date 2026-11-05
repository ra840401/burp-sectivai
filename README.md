<p align="center">
  <img src="src/main/resources/logo.png" width="88" alt="Sectiv logo">
</p>

<h1 align="center">Sectiv</h1>

<p align="center">
  <b>Skill-driven AI security review for Burp Suite</b><br>
  <sub>Capture traffic → pick a review goal → get a triaged vulnerability dashboard with AI findings, PoCs and reports.</sub>
</p>

<p align="center">
  <a href="https://sectiv.ai"><img alt="Website" src="https://img.shields.io/badge/Website-sectiv.ai-0B1115?style=for-the-badge&logo=google-chrome&logoColor=white"></a>
  <a href="https://www.youtube.com/@zack0x01"><img alt="YouTube" src="https://img.shields.io/badge/YouTube-zack0x01-FF0000?style=for-the-badge&logo=youtube&logoColor=white"></a>
  <a href="https://x.com/zack0x01_"><img alt="X" src="https://img.shields.io/badge/X-zack0x01_-000000?style=for-the-badge&logo=x&logoColor=white"></a>
  <a href="https://www.instagram.com/zack0X01/"><img alt="Instagram" src="https://img.shields.io/badge/Instagram-zack0X01-E4405F?style=for-the-badge&logo=instagram&logoColor=white"></a>
  <a href="https://www.buymeacoffee.com/zack0x01"><img alt="Buy Me a Coffee" src="https://img.shields.io/badge/Buy_Me_a_Coffee-zack0x01-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black"></a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-F47832?style=flat-square">
  <img alt="Burp Suite" src="https://img.shields.io/badge/Burp_Suite-Montoya_2026.7-FF6633?style=flat-square">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square">
</p>

---

<p align="center">
  <img src="design/dashboard-demo.png" alt="Sectiv dashboard" width="920">
</p>

## Install

1. Download **`release/sectiv-1.0.0.jar`**.
2. Burp Suite → **Extensions → Installed → Add** → type **Java** → select the JAR.
3. A **Sectiv** tab appears. Open **Settings**, paste your AI provider API key. Done.

## Features

- **Severity dashboard** — Critical / High / Medium / Low / Info, search, filters, triage status and HTML / Markdown / JSON export.
- **Scope picker** — load proxy history or site map, filter, collapse duplicates, remove static assets, tick the requests to review.
- **Skills** — built-in demo skills (IDOR, XSS, SQLi, SSRF, auth…) plus create, edit, import and export your own.
- **Structured findings** — description, steps to reproduce, impact, PoC (HTML / Python / curl), CWE/CVE and CVSS.
- **Identity context** — two accounts for BAC/IDOR reasoning, plus an optional deterministic identity-swap check.
- **Multiple providers** — DeepSeek, OpenAI, Claude, GLM, z.ai, OpenRouter, Ollama and any OpenAI-compatible endpoint.
- **Privacy controls** — cookies, tokens, keys and JWTs are masked before traffic is sent to the model.

## Use

1. **Settings** — pick a provider, set base URL + model, paste the API key, **Test connection**, save.
2. **Scan → Target scope** — load history or site map and tick the requests to review.
3. **Scan → Review goal** — pick a skill (or run all enabled).
4. **Scan → Identity context** — optionally paste two accounts for BAC/IDOR checks.
5. **Run scan** — findings appear live in the dashboard; export when done.

## Skills

The built-in skills are **demo examples** — add your own skills tailored to your target.

**Tip:** end every skill body with a validation instruction, for example:

> Before reporting a finding, confirm it against the captured evidence and explain what would validate it. If you cannot confirm it, mark it tentative or leave it out.

That one line eliminates most false positives.

## Build from source (developers)

Requires JDK 21.

```bash
./gradlew test          # unit + headless UI tests
./gradlew shadowJar     # builds build/libs/sectiv-1.0.0.jar
```

## Limitations

- This is an AI-assisted review — validate every finding before reporting it.
- The AI only reasons about the traffic you select; it cannot discover endpoints that are absent from that traffic.
