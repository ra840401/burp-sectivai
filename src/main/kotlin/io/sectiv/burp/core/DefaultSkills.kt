package io.sectiv.burp.core

/**
 * Built-in review goals ("skills"). They are deliberately written as review
 * instructions rather than exploit recipes: the model only sees captured
 * traffic, so every finding must be grounded in evidence from that traffic.
 */
fun defaultSkills(): List<Skill> = listOf(
    Skill(
        id = "skill-idor",
        name = "IDOR & BOLA",
        category = "Access control",
        description = "Object-level authorization: can one user reach another user's records by changing IDs, paths or body fields?",
        builtIn = true,
        instructions = """
            Review the captured traffic for Insecure Direct Object References and Broken Object Level Authorization.

            Focus on:
            - Numeric IDs, UUIDs, slugs, filenames, account/tenant/org IDs in paths, query strings, JSON bodies and headers.
            - Endpoints that return a single object or a list scoped to the caller (e.g. /api/users/{id}, /orders/{id}, /files/{id}).
            - Whether the server appears to derive the object owner from the session, or trusts a client-supplied identifier.
            - Sequential or enumerable identifiers and responses that expose another account's data.
            - Any evidence that User A's identifier appears in a response while authenticated as User B (or vice versa).

            Use the identity context to reason about which account sent the request and whose data came back. If the captured response contains a different user's email, name, account number or tenant ID than the requesting identity, report it.

            Only report an issue when the captured evidence supports it. Do not invent endpoints. If the evidence is suggestive but not conclusive (for example an ID is present but ownership cannot be verified from the traffic), report it with confidence "tentative" and explain exactly what additional request would confirm it.
        """.trimIndent()
    ),
    Skill(
        id = "skill-bfla",
        name = "Function-Level Authorization",
        category = "Access control",
        description = "Privilege escalation: are admin, internal or privileged actions reachable by lower-privileged users?",
        builtIn = true,
        instructions = """
            Review the captured traffic for Broken Function-Level Authorization and privilege escalation.

            Focus on:
            - Administrative, internal, support, debug, export and management endpoints or actions (e.g. /admin, /internal, /v1/users/delete, role changes, feature flags).
            - HTTP methods that perform privileged state changes (POST, PUT, PATCH, DELETE) on resources normally managed by staff.
            - Role, permission, tenant or plan parameters supplied by the client and whether they are trusted.
            - Responses that suggest a low-privileged identity successfully performed a privileged action (200/201/204 with a meaningful body, or a state change visible in a later response).
            - Force-browsing indicators: a 403 for one identity and a 200 for another on the same endpoint.

            Compare the identities in the identity context where possible. Only report issues grounded in the captured exchanges, and state what evidence is missing when the result is inconclusive.
        """.trimIndent()
    ),
    Skill(
        id = "skill-auth",
        name = "Authentication & Sessions",
        category = "Authentication",
        description = "Session handling, token lifecycle, MFA and password reset weaknesses visible in traffic.",
        builtIn = true,
        instructions = """
            Review the captured traffic for authentication and session management weaknesses.

            Focus on:
            - Session cookies missing Secure, HttpOnly or SameSite attributes; weak or predictable session identifiers.
            - Tokens or credentials in URLs, query strings, Referer headers or logs.
            - JWTs: algorithm confusion indicators, missing/invalid signature verification, long expiry, sensitive claims, tokens accepted after logout or password change.
            - Login, registration, password reset, email verification and MFA flows: user enumeration, reset-token leakage, missing rate limiting, bypasses, host-header injection in reset links.
            - Session fixation, missing rotation after login, and the same session surviving privilege changes.
            - Credentials or tokens returned in responses where they should not be.

            Base findings on the captured headers, cookies and bodies. Distinguish confirmed observations from hardening advice; hardening-only observations belong at severity low or info.
        """.trimIndent()
    ),
    Skill(
        id = "skill-sqli",
        name = "SQL Injection",
        category = "Injection",
        description = "SQL/NoSQL injection signals in parameters, JSON bodies and error responses.",
        builtIn = true,
        instructions = """
            Review the captured traffic for SQL and NoSQL injection.

            Focus on:
            - Parameters, JSON fields, headers and path segments that are likely used in database queries (id, sort, order, filter, search, username, email).
            - Database error messages, stack traces, syntax errors or ORM exceptions in responses.
            - Boolean, time-based or UNION indicators visible in paired requests/responses.
            - Differences between requests that suggest a parameter changes query structure.
            - NoSQL operator injection in JSON bodies (e.g. {"\${'$'}ne": null}, {"\${'$'}gt": ""}).

            Do not claim a parameter is injectable purely from its name. Report only what the traffic shows. If a parameter is a plausible candidate but the captures contain no confirming signal, report it at low confidence or omit it.
        """.trimIndent()
    ),
    Skill(
        id = "skill-xss",
        name = "Cross-Site Scripting",
        category = "Injection",
        description = "Reflected, stored and DOM XSS indicators where input is echoed into HTML/JS contexts.",
        builtIn = true,
        instructions = """
            Review the captured traffic for reflected, stored and DOM-based cross-site scripting.

            Report a finding whenever a request value (query parameter, body field, header, path segment) is echoed in the response body, even if the reflection is URL-encoded or HTML-entity-encoded. A reflected value inside an HTML or JavaScript context is a candidate XSS.

            Focus on:
            - Request values that appear verbatim (or lightly encoded) in HTML text, tag attributes, event handlers, script blocks, JSON embedded in HTML, or error messages.
            - HTML context: unencoded <, >, ", ', and event-handler / javascript: injection points. If the value is reflected into a tag attribute without proper quoting/encoding, report it.
            - JavaScript context: values echoed into string literals, template literals or script blocks (</script> breakout, single/double quote breakout, backtick breakout).
            - Stored flows where a value submitted in one request appears in a later response.
            - Content-Type and X-Content-Type-Options mismatches that make reflected input dangerous.
            - DOM sinks in captured JavaScript (innerHTML, document.write, eval, insertAdjacentHTML, location assignment, jQuery .html()) combined with a controllable source (location, URLSearchParams, document.referrer, postMessage data).

            Confidence rules:
            - Reflection into an unencoded HTML text or markup position -> confidence "certain" or "firm".
            - Reflection into a quoted attribute or JS string with a breakout character visible -> "firm".
            - Reflection that needs an additional condition (e.g. DOM sink without a visible source in the captured traffic) -> "tentative", but still report it and describe the confirming request.

            Quote the exact request value and the exact location it is reflected to. Do not wait for proof of script execution: reflection into an HTML/JS context is enough to report. If the captured traffic contains a page that reflects a parameter, report it even when the context looks partially encoded.
        """.trimIndent()
    ),
    Skill(
        id = "skill-ssrf",
        name = "SSRF & Outbound Requests",
        category = "Injection",
        description = "Server-side request forgery via URL, webhook, image or import parameters.",
        builtIn = true,
        instructions = """
            Review the captured traffic for server-side request forgery and unsafe outbound fetches.

            Focus on:
            - URL, webhook, callback, image, avatar, import, feed, PDF, proxy and "fetch remote" parameters.
            - Full URLs or hostnames in JSON/body parameters, including nested objects.
            - Responses that reveal fetched content, internal hostnames, cloud metadata, redirects or timing differences.
            - Open redirect parameters that could be chained into a server-side fetch.
            - Allow-list bypass indicators (userinfo @, decimal/hex IPs, IPv6, DNS rebinding-friendly hostnames).

            Only report SSRF when the captured traffic shows a user-controlled URL being fetched or a response consistent with server-side retrieval. Explain the required preconditions and the evidence that supports them.
        """.trimIndent()
    ),
    Skill(
        id = "skill-data",
        name = "Sensitive Data Exposure",
        category = "Data protection",
        description = "PII, secrets, tokens and internal details leaked in responses.",
        builtIn = true,
        instructions = """
            Review the captured traffic for sensitive data exposure.

            Focus on:
            - PII beyond what the endpoint should return: emails, phone numbers, addresses, government IDs, dates of birth, payment data, health data.
            - Credentials, API keys, JWTs, session tokens, cloud keys, private keys, database connection strings and internal hostnames in responses.
            - Debug/actuator/metrics endpoints, stack traces, framework versions and verbose errors.
            - Over-fetching: list endpoints returning full objects when a minimal representation is expected.
            - Sensitive data cached in responses without Cache-Control protections.
            - Cross-user data leakage, especially objects returned for an identifier that belongs to another account.

            Quote the exact leaked value (or a redacted prefix) and its location. Do not treat ordinary public profile fields as sensitive without context.
        """.trimIndent()
    ),
    Skill(
        id = "skill-logic",
        name = "Business Logic",
        category = "Business logic",
        description = "Race conditions, price/quantity manipulation, workflow bypass and state-machine flaws.",
        builtIn = true,
        instructions = """
            Review the captured traffic for business logic and workflow flaws.

            Focus on:
            - Price, discount, quantity, currency, shipping and total fields supplied by the client and accepted by the server.
            - Coupon or referral abuse, negative quantities, integer overflow, rounding issues.
            - Multi-step workflows where a later step can be reached without completing earlier steps.
            - State transitions (pending -> paid, trial -> active) driven by client-controlled parameters.
            - Race-condition candidates: duplicate submission of one-time actions, concurrent redemption, balance changes.
            - Missing server-side validation of limits, quotas or ownership during transfers.

            Report the business impact and the exact requests that demonstrate the flaw. Speculative logic concerns without supporting traffic should be omitted or reported as info with a clear rationale.
        """.trimIndent()
    ),
    Skill(
        id = "skill-params",
        name = "Mass Assignment",
        category = "Input validation",
        description = "Client-controlled fields that alter privileged object properties or bypass validation.",
        builtIn = true,
        instructions = """
            Review the captured traffic for mass assignment and unsafe parameter handling.

            Focus on:
            - JSON/XML bodies containing fields the client should not control: role, isAdmin, verified, approved, balance, credits, ownerId, tenantId, plan, permissions.
            - Extra fields accepted by update/profile/registration endpoints (mass assignment).
            - Type juggling, duplicate parameters, parameter pollution, unexpected content types.
            - Hidden fields, disabled inputs and server-side values mirrored to the client.
            - Validation performed only client-side that the captured request bypasses.

            Evidence must show the field being sent and a response suggesting it was accepted. If acceptance cannot be confirmed from the traffic, mark the finding tentative and describe the confirming test.
        """.trimIndent()
    ),
    Skill(
        id = "skill-files",
        name = "File Upload & Path Traversal",
        category = "Files",
        description = "Unrestricted uploads, traversal, local file inclusion and dangerous file handling.",
        builtIn = true,
        instructions = """
            Review the captured traffic for file upload and path traversal issues.

            Focus on:
            - Upload endpoints: content-type checks, extension checks, filename sanitisation, storage outside the web root, executable extensions.
            - Path traversal in download/export/preview parameters (../../, encoded variants, Windows separators, null bytes).
            - Local/remote file inclusion parameters, template selection, language or theme files.
            - Direct object references to files belonging to other users.
            - Responses exposing filesystem paths, generated filenames or storage bucket URLs.
            - Archive extraction endpoints that may allow zip-slip.

            Quote the request parameter and the response evidence. Do not assume an upload is dangerous solely because it exists; state which control appears to be missing or bypassable.
        """.trimIndent()
    )
)
