package org.example;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlAnalyzer {

    private static final String[] SUSPICIOUS_KEYWORDS = {
            "login", "verify", "secure", "account", "update", "bank", "confirm", "signin",
            "password", "invoice", "suspended", "urgent", "unlock", "billing", "security",
            "alert", "reset", "limited", "expire", "authenticate"
    };

    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
    };

    private static final String[] KNOWN_BRANDS = {
            "google", "facebook", "instagram", "amazon", "paypal", "microsoft", "apple",
            "netflix", "whatsapp", "youtube", "linkedin", "twitter", "ebay", "adobe",
            "dropbox", "spotify", "yahoo", "gmail", "outlook", "bankofamerica", "chase",
            "wellsfargo", "hdfcbank", "icicibank", "sbi", "flipkart", "snapchat"
    };

    private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(java.util.Arrays.asList(
            "google.com", "youtube.com", "facebook.com", "instagram.com", "amazon.com",
            "wikipedia.org", "microsoft.com", "apple.com", "netflix.com", "whatsapp.com",
            "linkedin.com", "twitter.com", "x.com", "github.com", "stackoverflow.com",
            "reddit.com", "yahoo.com", "gmail.com", "outlook.com", "paypal.com",
            "ebay.com", "adobe.com", "dropbox.com", "spotify.com", "flipkart.com",
            "wellsfargo.com", "chase.com", "bankofamerica.com"
    ));

    private static final int MAX_REDIRECTS = 5;
    private static final int TIMEOUT_MS = 4000;

    // Common two-part country-code TLDs where the "real" registrable name
    // sits one label further back than usual (e.g. "alliance.edu.in" — the
    // meaningful name is "alliance", not "edu"). Without this, typosquat
    // comparison would check the wrong segment for these very common
    // domain patterns.
    private static final Set<String> COMPOUND_TLDS = new HashSet<>(java.util.Arrays.asList(
            "co.in", "edu.in", "gov.in", "ac.in", "org.in", "net.in", "res.in",
            "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
            "com.au", "gov.au", "edu.au", "org.au",
            "co.jp", "co.nz", "com.br", "co.za"
    ));

    // OPTIMIZATION: precompiled once at class-load time instead of being
    // recompiled from a string pattern on every single call to isIpAddress checks.
    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    // OPTIMIZATION: a single shared HttpClient instance, reused across every
    // analyze() call for the life of the application. HttpClient (unlike the
    // older HttpURLConnection) supports underlying connection pooling, so
    // reusing one instance avoids repeatedly paying connection setup cost.
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(TIMEOUT_MS))
            .followRedirects(HttpClient.Redirect.NEVER) // we handle hops manually for SSRF checks + hop counting
            .build();

    private static Set<String> cachedBlacklist = null;

    public static AnalysisResult analyze(String originalUrlString) {
        List<String> reasons = new ArrayList<>();
        int score = 0;

        RedirectResult redirectResult = resolveFinalUrl(originalUrlString);
        String urlString = redirectResult.finalUrl;
        String lowerUrl = urlString.toLowerCase(); // computed once, reused below

        if (redirectResult.hopCount > 0) {
            reasons.add("URL redirects " + redirectResult.hopCount + " time(s) to: " + urlString);
            score += 5 * redirectResult.hopCount;
        }
        if (redirectResult.resolutionFailed) {
            reasons.add("Could not verify final destination (no response/timeout/blocked target) — analyzing original link only");
        }

        String host;
        try {
            URI uri = new URI(urlString);
            host = uri.getHost();
            if (host == null) {
                reasons.add("URL is malformed or missing a valid host");
                return new AnalysisResult("Malicious", 100, reasons);
            }
        } catch (Exception e) {
            reasons.add("URL could not be parsed: " + e.getMessage());
            return new AnalysisResult("Malicious", 100, reasons);
        }

        String lowerHost = host.toLowerCase();
        String normalizedHost = lowerHost.startsWith("www.") ? lowerHost.substring(4) : lowerHost;

        // 0.5 Trusted whitelist check — exact match only, skips all heuristics
        if (TRUSTED_DOMAINS.contains(normalizedHost)) {
            reasons.add("Domain is on the trusted whitelist");
            return new AnalysisResult("Safe", 0, reasons);
        }

        // 1. Blacklist check (checked against the FINAL resolved host)
        Set<String> blacklist = loadBlacklist();
        if (blacklist.contains(normalizedHost)) {
            reasons.add("Domain found in known-phishing blacklist");
            return new AnalysisResult("Malicious", 100, reasons);
        }

        // 2. HTTPS check
        if (!lowerUrl.startsWith("https://")) {
            score += 15;
            reasons.add("Does not use HTTPS");
        }

        // 3. IP address instead of domain (using precompiled pattern)
        boolean isIpAddress = IP_PATTERN.matcher(host).matches();
        if (isIpAddress) {
            score += 30;
            reasons.add("Uses an IP address instead of a domain name");
        }

        // 4. URL shortener check (matched against host boundaries, not raw substring)
        for (String shortener : SHORTENERS) {
            if (lowerHost.equals(shortener) || lowerHost.endsWith("." + shortener)) {
                score += 20;
                reasons.add("Uses a known URL shortener (" + shortener + ")");
                break;
            }
        }

        // 5. Suspicious keywords
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lowerUrl.contains(keyword)) {
                score += 10;
                reasons.add("Contains suspicious keyword: \"" + keyword + "\"");
            }
        }

        // 6. Excessive hyphens
        int hyphenCount = host.length() - host.replace("-", "").length();
        if (hyphenCount >= 2) {
            score += 15;
            reasons.add("Domain contains multiple hyphens (" + hyphenCount + ")");
        }

        // 7. Excessive subdomains (skip for IP hosts — not applicable).
        // Uses normalizedHost (www-stripped) so a normal "www.example.edu.in"
        // style address isn't penalized purely for having "www." in front.
        if (!isIpAddress) {
            long dotCount = normalizedHost.chars().filter(c -> c == '.').count();
            if (dotCount >= 3) {
                score += 15;
                reasons.add("Domain has an unusually high number of subdomains");
            }
        }

        // 8. Typosquat / brand-impersonation check
        if (!isIpAddress) {
            String coreDomain = extractCoreDomainName(normalizedHost);
            for (String brand : KNOWN_BRANDS) {
                if (coreDomain.equals(brand)) {
                    break;
                }
                int distance = levenshteinDistance(coreDomain, brand);
                boolean lengthClose = Math.abs(coreDomain.length() - brand.length()) <= 2;
                if (distance > 0 && distance <= 2 && lengthClose) {
                    score += 55;
                    reasons.add("Domain closely resembles known brand \"" + brand
                            + "\" (possible typosquatting, edit distance " + distance + ")");
                    break;
                }
            }
        }

        // 9. Lightweight live page content check — fetches the actual page
        // HTML (a normal GET, not a full browser) and looks for a password
        // field combined with a page title claiming to be a brand the
        // domain doesn't match. Fails silently if the page can't be
        // fetched (timeout, non-HTML content, blocked target, etc.) so it
        // never breaks the rest of the analysis.
        PageContentFindings pageFindings = analyzePageContent(urlString, normalizedHost);
        if (pageFindings != null) {
            score += pageFindings.score;
            reasons.addAll(pageFindings.reasons);
        }

        String verdict;
        if (score >= 50) {
            verdict = "Malicious";
        } else if (score >= 10) {
            verdict = "Suspicious";
        } else {
            verdict = "Safe";
            if (reasons.isEmpty()) {
                reasons.add("No significant phishing indicators found");
            }
        }

        return new AnalysisResult(verdict, score, reasons);
    }

    // Natural display names for the KNOWN_BRANDS keys, used to search page
    // titles (a title says "Bank of America", not "bankofamerica").
    private static final Map<String, String> BRAND_DISPLAY_NAMES = new HashMap<>();
    static {
        BRAND_DISPLAY_NAMES.put("google", "Google");
        BRAND_DISPLAY_NAMES.put("facebook", "Facebook");
        BRAND_DISPLAY_NAMES.put("instagram", "Instagram");
        BRAND_DISPLAY_NAMES.put("amazon", "Amazon");
        BRAND_DISPLAY_NAMES.put("paypal", "PayPal");
        BRAND_DISPLAY_NAMES.put("microsoft", "Microsoft");
        BRAND_DISPLAY_NAMES.put("apple", "Apple");
        BRAND_DISPLAY_NAMES.put("netflix", "Netflix");
        BRAND_DISPLAY_NAMES.put("whatsapp", "WhatsApp");
        BRAND_DISPLAY_NAMES.put("youtube", "YouTube");
        BRAND_DISPLAY_NAMES.put("linkedin", "LinkedIn");
        BRAND_DISPLAY_NAMES.put("twitter", "Twitter");
        BRAND_DISPLAY_NAMES.put("ebay", "eBay");
        BRAND_DISPLAY_NAMES.put("adobe", "Adobe");
        BRAND_DISPLAY_NAMES.put("dropbox", "Dropbox");
        BRAND_DISPLAY_NAMES.put("spotify", "Spotify");
        BRAND_DISPLAY_NAMES.put("yahoo", "Yahoo");
        BRAND_DISPLAY_NAMES.put("gmail", "Gmail");
        BRAND_DISPLAY_NAMES.put("outlook", "Outlook");
        BRAND_DISPLAY_NAMES.put("bankofamerica", "Bank of America");
        BRAND_DISPLAY_NAMES.put("chase", "Chase");
        BRAND_DISPLAY_NAMES.put("wellsfargo", "Wells Fargo");
        BRAND_DISPLAY_NAMES.put("hdfcbank", "HDFC Bank");
        BRAND_DISPLAY_NAMES.put("icicibank", "ICICI Bank");
        BRAND_DISPLAY_NAMES.put("sbi", "State Bank of India");
        BRAND_DISPLAY_NAMES.put("flipkart", "Flipkart");
        BRAND_DISPLAY_NAMES.put("snapchat", "Snapchat");
    }

    // Caps how much of a page's HTML we'll read, so a huge or slow page
    // can't stall analysis or waste bandwidth on a public-facing deployment.
    private static final int MAX_CONTENT_CHARS = 300_000;

    private static final Pattern TITLE_PATTERN =
            Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /**
     * Fetches the page's actual HTML with a normal GET request (not a full
     * browser — no JavaScript execution, no rendering) and checks for two
     * lightweight but meaningful signals: a password input field, and a
     * page title claiming to be a brand the domain doesn't actually match.
     * Returns null (contributing nothing) if the page can't be fetched for
     * any reason — network failure, timeout, non-HTML content, or an
     * SSRF-blocked internal target — so this step never breaks analysis.
     */
    private static PageContentFindings analyzePageContent(String urlString, String normalizedHost) {
        try {
            if (isPrivateOrInternalTarget(urlString)) {
                return null;
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(urlString))
                    .method("GET", HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofMillis(TIMEOUT_MS))
                    .header("User-Agent", "Mozilla/5.0 (QR-Phishing-Detector)")
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (!contentType.toLowerCase().contains("text/html")) {
                return null; // not a webpage (image, PDF, API response, etc.) — nothing to analyze
            }

            String html = response.body();
            if (html == null || html.isBlank()) {
                return null;
            }
            if (html.length() > MAX_CONTENT_CHARS) {
                html = html.substring(0, MAX_CONTENT_CHARS);
            }

            List<String> reasons = new ArrayList<>();
            int score = 0;

            boolean hasPasswordField = html.toLowerCase().contains("type=\"password\"")
                    || html.toLowerCase().contains("type='password'");
            if (hasPasswordField) {
                score += 10;
                reasons.add("Page contains a password input field");
            }

            Matcher titleMatcher = TITLE_PATTERN.matcher(html);
            if (titleMatcher.find()) {
                String pageTitle = titleMatcher.group(1).trim();
                String lowerTitle = pageTitle.toLowerCase();
                String coreDomain = extractCoreDomainName(normalizedHost);

                for (Map.Entry<String, String> brand : BRAND_DISPLAY_NAMES.entrySet()) {
                    String brandKey = brand.getKey();
                    String brandDisplay = brand.getValue();

                    if (lowerTitle.contains(brandDisplay.toLowerCase()) && !coreDomain.equals(brandKey)) {
                        score += 40;
                        reasons.add("Page title claims to be \"" + brandDisplay
                                + "\" but the domain does not match that brand");
                        break;
                    }
                }
            }

            return reasons.isEmpty() ? null : new PageContentFindings(score, reasons);

        } catch (Exception e) {
            return null; // timeout, connection refused, malformed response, etc. — fail silently
        }
    }

    private static class PageContentFindings {
        final int score;
        final List<String> reasons;

        PageContentFindings(int score, List<String> reasons) {
            this.score = score;
            this.reasons = reasons;
        }
    }

    private static String extractCoreDomainName(String normalizedHost) {
        String[] parts = normalizedHost.split("\\.");
        if (parts.length < 2) return normalizedHost;

        if (parts.length >= 3) {
            String lastTwoLabels = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (COMPOUND_TLDS.contains(lastTwoLabels)) {
                return parts[parts.length - 3];
            }
        }
        return parts[parts.length - 2];
    }

    private static int levenshteinDistance(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[a.length()][b.length()];
    }

    /**
     * Follows HTTP redirects (HEAD requests only — no content is ever
     * downloaded) up to MAX_REDIRECTS hops, using a shared, connection-pooled
     * HttpClient. Blocks any hop that resolves to a private/internal IP
     * address (SSRF protection). Falls back gracefully to the original URL
     * if resolution fails or is blocked.
     */
    private static RedirectResult resolveFinalUrl(String startUrl) {
        String currentUrl = startUrl;
        int hops = 0;

        if (!currentUrl.toLowerCase().startsWith("http://") && !currentUrl.toLowerCase().startsWith("https://")) {
            return new RedirectResult(startUrl, 0, false);
        }

        try {
            for (int i = 0; i < MAX_REDIRECTS; i++) {

                if (isPrivateOrInternalTarget(currentUrl)) {
                    return new RedirectResult(currentUrl, hops, true);
                }

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(currentUrl))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .timeout(Duration.ofMillis(TIMEOUT_MS))
                        .header("User-Agent", "Mozilla/5.0 (QR-Phishing-Detector)")
                        .build();

                HttpResponse<Void> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.discarding());
                int status = response.statusCode();

                boolean isRedirect = (status == 301 || status == 302 || status == 303
                        || status == 307 || status == 308);

                if (!isRedirect) {
                    return new RedirectResult(currentUrl, hops, false);
                }

                var locationHeader = response.headers().firstValue("Location");
                if (locationHeader.isEmpty()) {
                    return new RedirectResult(currentUrl, hops, false);
                }

                URI resolved = URI.create(currentUrl).resolve(locationHeader.get());
                currentUrl = resolved.toString();
                hops++;
            }
            return new RedirectResult(currentUrl, hops, false);

        } catch (Exception e) {
            return new RedirectResult(startUrl, hops, true);
        }
    }

    /**
     * Returns true if the URL's host resolves to a private, loopback, or
     * link-local IP address — prevents this service from being abused as
     * an SSRF vector to probe internal infrastructure.
     */
    private static boolean isPrivateOrInternalTarget(String urlString) {
        try {
            String host = URI.create(urlString).getHost();
            if (host == null) return true;

            java.net.InetAddress address = java.net.InetAddress.getByName(host);
            return address.isLoopbackAddress()
                    || address.isSiteLocalAddress()
                    || address.isLinkLocalAddress()
                    || address.isAnyLocalAddress()
                    || address.isMulticastAddress();
        } catch (Exception e) {
            return true;
        }
    }

    private static Set<String> loadBlacklist() {
        if (cachedBlacklist != null) {
            return cachedBlacklist;
        }
        Set<String> domains = new HashSet<>();
        try (InputStream is = UrlAnalyzer.class.getClassLoader().getResourceAsStream("blacklist.txt")) {
            if (is == null) return domains;
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String extractedHost = extractHostFromBlacklistLine(line);
                if (extractedHost != null && !extractedHost.isEmpty()) {
                    domains.add(extractedHost);
                }
            }
        } catch (Exception e) {
            System.out.println("Warning: could not load blacklist - " + e.getMessage());
        }
        cachedBlacklist = domains;
        return domains;
    }

    private static String extractHostFromBlacklistLine(String line) {
        try {
            String host;
            if (line.contains("://")) {
                host = URI.create(line).getHost();
            } else {
                host = line.split("/")[0];
            }
            if (host == null) return null;
            host = host.toLowerCase();
            if (host.startsWith("www.")) {
                host = host.substring(4);
            }
            return host;
        } catch (Exception e) {
            return null;
        }
    }

    private static class RedirectResult {
        final String finalUrl;
        final int hopCount;
        final boolean resolutionFailed;

        RedirectResult(String finalUrl, int hopCount, boolean resolutionFailed) {
            this.finalUrl = finalUrl;
            this.hopCount = hopCount;
            this.resolutionFailed = resolutionFailed;
        }
    }

    public static class AnalysisResult {
        public final String verdict;
        public final int score;
        public final List<String> reasons;

        public AnalysisResult(String verdict, int score, List<String> reasons) {
            this.verdict = verdict;
            this.score = score;
            this.reasons = reasons;
        }
    }
}