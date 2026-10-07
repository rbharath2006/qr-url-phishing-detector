# 🛡️ QR Phishing Detector

> **Scan smart. Inspect first. Stay phish-proof.**

A Java-based QR phishing detection system that analyzes suspicious URLs obtained from **QR code images** or **directly pasted URLs**. The system resolves redirect chains, checks multiple phishing indicators, applies blacklist/whitelist logic, performs typosquat detection, and presents a clear security verdict.

The project is available through both a **desktop Java Swing application** and a **browser-based web interface**, with both interfaces powered by the same core detection engine.

---

## 🌐 Live Demo

### 🚀 [Open QR Phishing Detector](https://qr-url-phishing-detector.onrender.com/)

**Live URL:**  
https://qr-url-phishing-detector.onrender.com/

> **Safety note:** This application is intended for cybersecurity learning, phishing detection, and awareness. Do not enter passwords, OTPs, banking information, or other sensitive information into unfamiliar websites.

---

## 🎯 Project Objective

QR codes are convenient, but they can hide the real destination behind a visual square. Attackers can replace legitimate QR codes with malicious ones that redirect users to fake login pages, payment pages, credential-harvesting websites, or other unsafe destinations.

The goal of this project is to make the destination visible and understandable **before the user trusts it**.

### High-level workflow

```text
             QR Code Image
                   │
                   ▼
             QR Decoder
                   │
                   ▼
              Extract URL
                   │
                   ├──────────────┐
                   │              │
                   ▼              ▼
               URL Input     Direct URL Input
                   │              │
                   └──────┬───────┘
                          ▼
                  Detection Engine
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
      Redirect        Blacklist /     Heuristic &
      Analysis        Whitelist       Typosquat
          │               │               │
          └───────────────┼───────────────┘
                          ▼
                    Final Verdict
                          │
                    ┌─────┴─────┐
                    ▼           ▼
                Desktop       Web UI
```

---

# ✨ Key Features

## 📷 Dual Input

The detector supports two input methods:

- **QR code image** — decode an uploaded QR image and extract the embedded URL.
- **Direct URL** — paste a URL manually.

Both inputs feed the same URL analysis pipeline.

## 🔗 Redirect-Chain Resolution

The system follows HTTP redirects for up to **5 hops** using lightweight `HEAD` requests to reveal the true final destination before analysis.

Example:

```text
https://short.example/abc
          ↓
https://redirect.example/login
          ↓
https://fake-bank.example/verify
          ↓
Final Destination
```

This helps expose destinations that are hidden behind redirect links or URL shorteners.

## 🧠 Hybrid Phishing Detection Engine

The detection engine combines several signals instead of depending on a single rule.

### 1. Blacklist Matching

A local blacklist contains known phishing domains. The blacklist is loaded and cached in memory after the first read.

### 2. Trusted-Domain Whitelist

A trusted-domain list helps reduce false positives for well-known legitimate domains.

### 3. Weighted Heuristic Scoring

The analyzer checks characteristics such as:

- HTTPS presence
- IP-address hosts
- Known URL shorteners
- Suspicious keywords
- Excessive hyphens
- Excessive subdomains

These signals contribute to the overall risk assessment.

### 4. Typosquat / Brand-Impersonation Detection

The project uses **Levenshtein edit distance** against a list of commonly impersonated brands.

Conceptually:

```text
Legitimate brand/domain
          +
Candidate hostname
          ↓
 Edit-distance comparison
          ↓
Very similar?
          ↓
Potential impersonation
```

This helps identify domains created to look similar to legitimate brands.

## 🔐 SSRF Protection

Before the service makes an outbound redirect-resolution request, the target is checked against private, loopback, and link-local IP ranges.

If the destination falls into a protected internal range, the request is refused.

This reduces the risk of the URL analyzer being abused to probe internal network infrastructure.

## 🚦 Rate Limiting

The web interface limits each visitor IP to:

```text
20 requests per minute
```

using an in-memory sliding window.

This helps protect the service from excessive requests by a single source.

## 🖥️ Two Interfaces

### Desktop GUI

Built with:

- Java Swing
- FlatLaf dark theme
- Color-coded verdicts
- Scan history panel

### Web Interface

Built with:

- JDK's embedded `com.sun.net.httpserver`
- Browser-based HTML/CSS/JavaScript dashboard
- Shared detection logic with the desktop application
- Background operation with system-tray controls

## 🧪 Automated Testing

The repository includes **9 JUnit 5 tests** covering the detection methods, including regression tests for two bugs discovered and fixed during development.

---

# ⚙️ Detailed Working of the Project

The project can be understood as a sequence of analysis stages.

## Stage 1 — Input Collection

The user selects one of two paths.

### Path A: QR Code

```text
QR Image
   ↓
ZXing Decoder
   ↓
Embedded text / URL
   ↓
URL Analyzer
```

ZXing (`core` + `javase`) is used to decode the QR code.

### Path B: Direct URL

```text
User pastes URL
       ↓
URL Analyzer
```

No QR decoding is needed for this path.

---

## Stage 2 — URL Parsing

The supplied URL is parsed so the application can inspect its important components, especially the hostname.

The analyzer can inspect:

```text
Protocol
Hostname
Path
Query
Redirect destination
```

The hostname is important because many phishing attacks rely on deceptive domain structures.

---

## Stage 3 — SSRF Safety Check

Before resolving redirects, the target is checked for protected address ranges.

```text
Target URL
    ↓
Private / loopback / link-local?
    │
    ├── YES → Refuse outbound resolution
    │
    └── NO  → Continue analysis
```

This is a security control around the analyzer itself.

---

## Stage 4 — Redirect Resolution

The application uses Java's `java.net.http.HttpClient` to resolve HTTP redirects.

The resolver follows up to **5 hops**.

```text
Hop 0
https://short.example/a1
       ↓
Hop 1
https://redirect.example/login
       ↓
Hop 2
https://account.example/verify
       ↓
Final destination
```

The destination obtained after redirect resolution can then be analyzed as part of the detection process.

---

## Stage 5 — Blacklist Matching

The extracted hostname is compared against the local phishing blacklist.

Simplified process:

```text
URL
 ↓
Extract hostname
 ↓
Normalize / parse blacklist entries
 ↓
Compare
 ↓
Known phishing domain?
```

During development, a blacklist matching problem was discovered where full URL entries such as:

```text
https://example.com
```

did not match the bare hostname used by the comparison logic.

The implementation was corrected by parsing the blacklist entry and extracting its host.

---

## Stage 6 — Trusted-Domain Check

The hostname is also checked against the trusted-domain whitelist.

This provides another layer of context and helps reduce unnecessary warnings for well-known legitimate sites.

---

## Stage 7 — Heuristic Analysis

Multiple URL characteristics are evaluated.

```text
HTTPS?
  ↓
IP address used as host?
  ↓
Known shortener?
  ↓
Suspicious keywords?
  ↓
Excessive hyphens?
  ↓
Excessive subdomains?
  ↓
Other suspicious structure?
```

The signals are combined through weighted scoring.

This means one weak signal does not have to determine the entire result; multiple suspicious characteristics can accumulate into a stronger risk indication.

---

## Stage 8 — Typosquat Detection

Attackers often create domains that look almost identical to legitimate organizations.

The project uses Levenshtein edit distance to compare candidate names against commonly impersonated brands.

```text
Brand/domain list
      ↓
Candidate hostname
      ↓
Edit distance
      ↓
High similarity?
      ↓
Potential typosquatting
```

This adds an additional defense against brand impersonation.

---

## Stage 9 — Combine Detection Signals

The final analysis combines the available evidence:

```text
Blacklist
    +
Whitelist
    +
Redirect analysis
    +
HTTPS / host heuristics
    +
Keyword signals
    +
Domain-structure signals
    +
Typosquat detection
            ↓
      Detection Engine
            ↓
       Final Verdict
```

The result is presented through the desktop or web interface.

---

# 🧩 System Architecture

```text
                         ┌─────────────────┐
                         │      USER       │
                         └────────┬────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
               QR Image                    Direct URL
                    │                           │
                    ▼                           │
               ZXing Decoder                    │
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                         URL Detection Engine
                                  │
                  ┌───────────────┼───────────────┐
                  │               │               │
                  ▼               ▼               ▼
             Redirect        Blacklist /      Heuristic /
             Resolver        Whitelist        Typosquat
                  │               │               │
                  └───────────────┼───────────────┘
                                  ▼
                             Verdict
                                  │
                   ┌──────────────┴──────────────┐
                   ▼                             ▼
              Desktop GUI                    Web Interface
```

---

# 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| **Java 25** | Core application and detection engine |
| **Maven** | Dependency/build management |
| **ZXing** | QR code decoding |
| **FlatLaf** | Modern dark Swing interface |
| **com.sun.net.httpserver** | Embedded Java web server |
| **java.net.http.HttpClient** | HTTP requests and redirect resolution |
| **JUnit 5** | Automated testing |

---

# 📁 Project Structure

```text
src/
├── main/
│   ├── java/
│   │   └── org/example/
│   │       ├── Main.java
│   │       ├── UrlAnalyzer.java
│   │       ├── AppGUI.java
│   │       └── WebServer.java
│   │
│   └── resources/
│       ├── blacklist.txt
│       └── web/
│           ├── index.html
│           └── background_cs.jpg
│
└── test/
    └── java/
        └── org/example/
            └── UrlAnalyzerTest.java
```

### Core components

- `Main.java` — QR decoding and console entry point
- `UrlAnalyzer.java` — blacklist, whitelist, heuristics, typosquat detection, redirect resolution, and SSRF protection
- `AppGUI.java` — desktop Swing interface
- `WebServer.java` — embedded HTTP server and web API
- `blacklist.txt` — local known-phishing-domain data
- `index.html` — browser-based frontend
- `UrlAnalyzerTest.java` — JUnit test suite

---

# ▶️ Running the Project Locally

## Prerequisites

Install:

```text
Java 25
Maven
```

An active internet connection is also required for operations/tests that perform real redirect resolution.

## Build and test

From the project root:

```bash
mvn clean test
```

Create the packaged build:

```bash
mvn clean package
```

The repository contains both the desktop application and the browser-based web interface; `WebServer.java` is responsible for the embedded web interface.

---

# 🧪 Testing

The project includes a JUnit 5 suite covering the detection methods.

In IntelliJ IDEA:

```text
src/test/java/org/example/
          ↓
UrlAnalyzerTest.java
          ↓
Run 'UrlAnalyzerTest'
```

Some redirect-resolution tests depend on live HTTP requests and therefore require internet connectivity.

---

# ⚡ Performance Optimizations

## Blacklist caching

The blacklist is loaded once and retained in memory instead of being read from disk for every scan.

## Precompiled regular expression

The IP-address detection pattern is compiled once during class loading.

## Shared HTTP client

A shared `java.net.http.HttpClient` is used for redirect resolution, allowing HTTP resources to be reused.

## Reduced redundant string processing

The lowercase representation of the URL is computed once per scan and reused by multiple checks.

## Concurrent request handling

The web server uses a fixed thread pool so multiple visitors/requests can be served concurrently.

---

# 🐛 Bugs Found and Fixed

## 1. Shortener false positive

### Problem

A legitimate domain such as:

```text
microsoft.com
```

could be incorrectly flagged as using the `t.co` shortener because of raw substring matching.

### Fix

Shortener detection was changed to match shortener domains using proper hostname/domain boundaries rather than simple substring matching.

## 2. Blacklist matching failure

### Problem

Blacklist entries stored as complete URLs were not matching the bare host used during comparison.

### Fix

Blacklist entries are parsed and their hostnames are extracted before comparison.

Both fixes are covered by permanent regression tests.

---

# ⚠️ Known Limitations

The current implementation has several known areas for future improvement:

- The blacklist is a static local sample file and is not connected to a live threat-intelligence feed.
- Domain-age / WHOIS analysis is not implemented yet.
- Full Unicode homograph detection is not implemented yet.
- Some automated tests depend on real network access for redirect resolution.
- Production deployments should place the service behind HTTPS and a suitable reverse proxy/platform configuration.

---

# 🚀 Future Scope

The detector can be expanded into a more comprehensive phishing-defense platform.

```text
Live Threat Intelligence
          ↓
Domain Age / WHOIS
          ↓
DNS Reputation
          ↓
Unicode Homograph Detection
          ↓
ML / AI Phishing Classification
          ↓
Browser Extension
          ↓
Mobile QR Scanner
          ↓
Database-backed History
          ↓
Security Analytics Dashboard
```

Potential future additions include:

- OpenPhish or PhishTank integration
- Live URL reputation services
- Domain registration-age analysis
- DNS and certificate analysis
- Unicode homograph detection
- Machine-learning phishing classification
- Browser extension support
- Mobile QR scanning
- Database-backed scan history
- Advanced security analytics

---

# 🔐 Phishing Awareness

QR phishing is often called **quishing**.

A QR code itself is not proof that a destination is safe. Users should be particularly careful with QR codes from:

- Unexpected emails
- Unverified messages
- Random posters or stickers
- Payment requests
- Login or verification prompts
- Messages that create urgency or fear

## 7-Second Safety Check

```text
01. Pause before scanning an unknown QR code.
02. Read the complete destination domain carefully.
03. Watch for misspellings and lookalike domains.
04. Be cautious with shortened URLs.
05. Never share passwords or OTPs because a QR prompt asks for them.
06. Verify payment recipients and amounts independently.
07. If something feels suspicious, close it.
```

---

# 🌍 Deployment

The project is currently deployed as a live web application:

### 🚀 Live Application

**https://qr-url-phishing-detector.onrender.com/**

The deployed interface allows users to access the detector without setting up the Java project locally.

For production-grade deployment, HTTPS should be used and sensitive API credentials should remain server-side rather than being embedded into browser code.

---

# 🎓 Academic and Practical Value

This project demonstrates practical application of:

- QR security
- URL analysis
- Phishing detection
- Redirect-chain analysis
- Domain reputation
- Typosquatting detection
- Levenshtein distance
- SSRF protection
- Rate limiting
- Java networking
- Desktop GUI development
- Web application development
- Automated testing
- Cybersecurity awareness

It combines **cybersecurity, Java development, networking, and web development** into one practical application.

---

# 🏁 Conclusion

The QR Phishing Detector is built around one simple principle:

> **Make the hidden destination visible before the user trusts it.**

Instead of assuming a QR code is safe, the system extracts its destination, resolves redirects, checks known phishing domains, evaluates URL characteristics, looks for brand impersonation, protects its own outbound requests, and presents the findings through an accessible user interface.

The result is more than a QR scanner: it is a **URL analysis, phishing detection, and security-awareness system**.

---

# 🔗 Project Links

**Live Web App:**  
https://qr-url-phishing-detector.onrender.com/

**GitHub Repository:**  
_Add your GitHub repository URL here._

---

## 📄 License

Add your preferred license here, for example:

```text
MIT License
```
