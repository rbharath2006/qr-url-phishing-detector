# QR Phishing Detector

A Java-based system that detects potential phishing links from a QR code image or a directly pasted URL — resolving the full redirect chain and running a hybrid blacklist, heuristic, and typosquat-detection engine before showing a verdict. Available as both a desktop Swing application and a browser-based web interface, both powered by the same core detection engine.

## Features

- **Dual input** — decode a QR code image (via ZXing) or paste a URL directly; both feed into one unified analysis pipeline.
- **Redirect-chain resolution** — follows HTTP redirects (lightweight HEAD requests, up to 5 hops) to reveal the true final destination before analysis, closing a gap that even commercial QR scanners are documented to have.
- **Hybrid detection engine**:
  - Blacklist matching against a local list of known-phishing domains (cached in memory after first load)
  - Trusted-domain whitelist to eliminate false positives on well-known sites
  - Weighted heuristic scoring: HTTPS presence, IP-address hosts, known URL shorteners (matched by domain boundary, not substring), suspicious keywords, excessive hyphens/subdomains
  - Typosquat / brand-impersonation detection using Levenshtein edit-distance against a list of commonly-impersonated brands
- **SSRF protection** — before making any outbound redirect-resolution request, the target is checked against private/loopback/link-local IP ranges and refused if it matches, so the service can't be abused to probe internal network infrastructure.
- **Two interfaces**:
  - **Desktop GUI** (`AppGUI.java`) — dark, cybersecurity-themed Java Swing app (via FlatLaf) with a color-coded verdict banner and scan history panel.
  - **Web interface** (`WebServer.java`) — an embedded Java HTTP server (built on the JDK's own `com.sun.net.httpserver`, no external framework) serving a browser-based HTML/CSS/JS dashboard with the same detection logic underneath. Runs in the background with a system tray icon (open/quit controls) rather than a visible console window.
- **Rate limiting** — the web interface limits each visitor IP to 20 requests per minute (in-memory sliding window), protecting the service from being overwhelmed by a single source.
- **Automated test suite** — 9 JUnit 5 tests covering every detection method, including regression tests for two real bugs found and fixed during development.

## Tech Stack

- Java 25
- Maven
- ZXing (`core` + `javase`) — QR decoding
- FlatLaf — modern dark theme for the desktop Swing app
- `com.sun.net.httpserver` — embedded web server (JDK built-in, no extra dependency)
- `java.net.http.HttpClient` — modern HTTP client with connection pooling, used for redirect resolution
- JUnit 5 — automated testing


## Running Tests

Right-click `UrlAnalyzerTest` in `src/test/java/org/example/` → **Run 'UrlAnalyzerTest'**. Requires an active internet connection, since redirect resolution performs real HTTP requests.

## Project Structure

```
src/main/java/org/example/
  Main.java          — QR decoding + console entry point
  UrlAnalyzer.java   — detection engine (blacklist, whitelist, heuristics, typosquat,
                        redirect resolution, SSRF protection)
  AppGUI.java        — desktop Swing GUI (dark cybersecurity theme, scan history)
  WebServer.java     — embedded web server + API, serves the browser-based frontend
src/main/resources/
  blacklist.txt      — local list of known-phishing domains
  web/
    index.html       — browser-based frontend (dashboard UI)
    background_cs.jpg — background image for the web UI
src/test/java/org/example/
  UrlAnalyzerTest.java — JUnit test suite
```

## Performance Optimizations

- **Blacklist caching** — loaded from disk once and kept in memory, instead of re-reading the file on every scan.
- **Precompiled regex** — the IP-address detection pattern is compiled once at class load rather than recompiled on every check.
- **Shared, connection-pooled HTTP client** — redirect resolution uses a single reused `java.net.http.HttpClient` instance instead of opening a fresh connection object per request.
- **Reduced redundant string operations** — the URL's lowercase form is computed once per scan and reused across multiple checks, rather than being recomputed for each one.
- **Concurrent request handling** — the web server uses a fixed thread pool instead of the single-threaded default, so multiple visitors/requests can be served at the same time instead of queuing.

## Known Limitations / Future Scope

- Blacklist is a static local sample file — not connected to a live threat-intelligence feed (future: integrate OpenPhish/PhishTank API)
- No domain-age (WHOIS) checking yet — newly registered domains are strong phishing indicators
- No Unicode homograph detection (visually identical characters from other alphabets)
- Automated tests depend on live network access for redirect resolution; a future version could use dependency injection to mock the network layer for fully offline testing
- Web version currently runs over plain HTTP, intended for local use or deployment behind a reverse proxy / hosting platform that terminates HTTPS (not yet deployed publicly)

## Bugs Found & Fixed During Development

- **Shortener false positive** — `microsoft.com` was incorrectly flagged as using the `t.co` shortener due to raw substring matching. Fixed by matching shortener domains at proper host boundaries.
- **Blacklist matching failure** — blacklist entries stored as full URLs (e.g. `https://example.com`) were never matching against the bare domain used for comparison. Fixed by properly parsing each blacklist line to extract just its host.

Both fixes are now covered by permanent regression tests in `UrlAnalyzerTest.java`.