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
  <a href="https://www.instagram.com/zacl0x01/"><img alt="Instagram" src="https://img.shields.io/badge/Instagram-zacl0x01-E4405F?style=for-the-badge&logo=instagram&logoColor=white"></a>
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

## Install (users)

No JDK, no build — just load the JAR:

1. Download **`release/sectiv-1.0.0.jar`** (or get it from the GitHub Releases page).
2. Open Burp Suite → **Extensions → Installed**.
3. Click **Add** → extension type **Java** → select the JAR.
4. A **Sectiv** tab appears. Open **Settings**, paste your AI provider API key, and you're ready to scan.

> The JAR is compiled against the Montoya API `2026.7` and Java 21. Use a current Burp release; older releases may reject it.

## Features

- **Severity dashboard** — Critical, High, Medium, Low and Info counters, filterable tables, search, status triage (Open / Triaged / False positive / Resolved) and HTML / Markdown / JSON export.
- **Scope picker** — load proxy history or site map, filter by host/path/method, restrict to Burp scope, collapse duplicate endpoints, remove static assets, and tick the requests to review.
- **Skills** — built-in review goals for BOLA/IDOR, function-level authorization, authentication/session issues, SQLi, XSS, SSRF, sensitive data exposure, business logic, mass assignment and file handling. Create, edit, duplicate, import and export your own Markdown skills.
- **Goal-based scanning** — run one skill or a full sweep of all enabled skills. Traffic is packed into token-budgeted chunks, with progress, cancellation and a live run log.
- **Structured findings** — every finding includes description, steps to reproduce, impact, a ready-to-use PoC (HTML page, Python script or curl command), CWE/CVE references and CVSS.
- **Identity context** — paste emails, cookies and authorization headers for User A and User B. The model uses this for BAC/IDOR reasoning, and Sectiv can optionally perform a deterministic **identity-swap check**: replay selected requests with User B's credentials and compare responses with User A's.
- **Multiple providers** — DeepSeek, Claude (Anthropic), OpenAI, GLM (Zhipu), z.ai, OpenRouter, local Ollama and any custom OpenAI-compatible endpoint.
- **Privacy controls** — cookie values, authorization headers, passwords, API keys and JWTs are masked before traffic is sent to the model. Email addresses are deliberately kept because they are a primary BOLA/IDOR signal. Masking can be disabled in Settings.
- **Safe defaults** — active identity-swap checks are off by default, require explicit confirmation, only use GET/HEAD/OPTIONS unless enabled otherwise, and are rate-limited.

## Use

1. **Settings → AI provider** — choose a provider, set the base URL/model, paste an API key, and use **Test connection**. Save.
2. **Scan → Target scope** — load proxy history or the site map, filter and tick the requests to review. **In scope** selects only items inside Burp's target scope.
3. **Scan → Review goal** — choose one skill, or enable **Run all enabled skills**.
4. **Scan → Identity context** — optionally paste two accounts. The template inserts a parseable layout:
   ```
   User A
     email: alice@example.com
     Cookie: session=...
     Authorization: Bearer ...

   User B
     email: bob@example.com
     Cookie: session=...
     Authorization: Bearer ...
   ```
   One-line notes such as `User A cookie is: session=...` are also parsed.
5. Click **Run scan**. Findings appear immediately in the dashboard as chunks complete.
6. Optionally enable **Verify with identity swap**. Sectiv replays the selected success responses with User B's credentials and flags responses that still return User A's data. You are asked to confirm the request count first.
7. Triage in **Dashboard**, then export an HTML, Markdown or JSON report.

## How the AI review works

The model does not issue requests by itself. Sectiv builds a prompt from:

- the selected skill's review instructions,
- the tester's identity context,
- redacted captured HTTP request/response pairs, packed into chunks that fit the configured character budget.

The system prompt requires a single JSON object, forbids inventing endpoints and treats captured traffic as untrusted data (prompt-injection defence). Sectiv parses the response defensively, deduplicates findings by fingerprint, and retries once with a stricter prompt if the model returns malformed JSON.

The identity-swap check is separate and deterministic: Sectiv replaces the matching session cookie or authorization header with User B's value, sends the request through Burp, and compares status, length and response similarity. Findings are marked `active check` in the dashboard and include the exact request that was sent.

## Data and privacy

- State is stored at `~/.sectiv/state.json` and written atomically with `0600` permissions where the filesystem supports them.
- The file contains settings, API keys, skills, the last identity context and all findings (including capped raw request/response excerpts). **It is not encrypted.** Use a dedicated API key and rotate it if the host is shared.
- The state file is global to the Burp installation, not per project. Use export before switching engagements, and clear findings when appropriate.
- Captured traffic is sent to the configured AI provider. Confirm that this is allowed for your engagement before scanning. Use **Settings → Scan behavior → Mask cookies and tokens** (on by default) and review the selected scope.
- Identity-swap checks send real traffic with the second account's credentials. Only run them against systems you are authorized to test.

## Project layout

```
src/main/kotlin/io/sectiv/burp/
  SectivExtension.kt        Burp entry point
  core/                     models, state, identity parsing, redaction, transcript
  ai/                       prompt building, finding parser, provider HTTP client
  scan/                     history collection, scan orchestration, identity swap
  ui/                       custom Swing dashboard, scan, skills and settings tabs
  report/                   HTML, Markdown and JSON reports
src/test/kotlin/            unit, scan-pipeline and headless UI tests
```

## Build from source (developers)

Only needed if you want to compile the extension yourself. Requirements: JDK 21 and network access for the first Gradle run.

```bash
./gradlew test          # unit + headless UI tests
./gradlew shadowJar     # build the loadable extension
```

The extension JAR is written to:

```
build/libs/sectiv-1.0.0.jar
```

The JAR bundles the Kotlin runtime and a relocated copy of Jackson. The Montoya API is compiled against but not bundled; Burp provides it at runtime.

## Limitations

- This is an **AI-assisted review**, not a replacement for Burp Scanner or manual testing. Validate every finding before reporting it.
- The AI only reasons about the traffic you select; it cannot discover endpoints that are absent from that traffic.
- Active identity-swap checking is a heuristic. A high-similarity response can still be a public or shared resource; the finding text tells you to confirm ownership.
- Model names and endpoints change. If **Test connection** fails, update the model identifier in Settings.
- AI calls can be slow or expensive. Use a focused scope and one skill at a time for large engagements.

## Development notes

- `./gradlew test` runs 40+ tests including redaction, identity parsing, prompt chunking, report escaping, persistence, the full scan pipeline with a fake model, and a headless Swing smoke test.
- The UI uses no third-party look-and-feel. Colors adapt to Burp's dark/light theme via `UserInterface.currentTheme()`.
- To add a provider preset, edit `defaultProviders()` in `core/Models.kt`. To add a built-in skill, edit `core/DefaultSkills.kt`.
