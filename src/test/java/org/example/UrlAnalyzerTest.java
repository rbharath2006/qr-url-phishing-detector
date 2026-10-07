package org.example;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Formal test suite for UrlAnalyzer, covering each detection method
 * independently. Note: because analyze() performs a real HEAD request
 * for redirect resolution, these tests require an active internet
 * connection. If offline, resolveFinalUrl() fails gracefully and the
 * tests should still pass against the original (unresolved) URL —
 * but a slow/unavailable network may make tests take longer to run.
 */
class UrlAnalyzerTest {

    @Test
    @Timeout(15)
    void trustedDomainIsSafe() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://www.wikipedia.org");
        assertEquals("Safe", result.verdict);
        assertEquals(0, result.score);
    }

    @Test
    @Timeout(15)
    void blacklistedDomainIsMalicious() {
        // Must exactly match a domain present in blacklist.txt
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://google1208.com");
        assertEquals("Malicious", result.verdict);
        assertTrue(result.reasons.stream().anyMatch(r -> r.contains("blacklist")));
    }

    @Test
    @Timeout(15)
    void ipAddressHostIsFlagged() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("http://192.168.1.1/login");
        assertNotEquals("Safe", result.verdict);
        assertTrue(result.reasons.stream().anyMatch(r -> r.contains("IP address")));
    }

    @Test
    @Timeout(15)
    void legitimateDomainIsNotFalselyFlaggedAsShortener() {
        // Regression test: "microsoft.com" contains the substring "t.co"
        // (a known shortener) but must NOT be flagged — host-boundary
        // matching, not raw substring matching, must be used.
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://www.microsoft.com");
        assertEquals("Safe", result.verdict);
        assertTrue(result.reasons.stream().noneMatch(r -> r.contains("shortener")));
    }

    @Test
    @Timeout(15)
    void typosquatOfKnownBrandIsFlagged() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://instaagram.com");
        assertNotEquals("Safe", result.verdict);
        assertTrue(result.reasons.stream().anyMatch(r -> r.contains("typosquatting")));
    }

    @Test
    @Timeout(15)
    void exactBrandMatchIsNotFlaggedAsTyposquat() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://www.instagram.com");
        assertTrue(result.reasons.stream().noneMatch(r -> r.contains("typosquatting")));
    }

    @Test
    @Timeout(15)
    void suspiciousKeywordIsDetected() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("https://paypal-verify.com");
        assertTrue(result.reasons.stream().anyMatch(r -> r.contains("verify")));
    }

    @Test
    @Timeout(15)
    void malformedUrlIsTreatedAsMalicious() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("not a valid url");
        assertEquals("Malicious", result.verdict);
        assertEquals(100, result.score);
    }

    @Test
    @Timeout(15)
    void missingHttpsIsPenalized() {
        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze("http://example-test-plain.com");
        assertTrue(result.reasons.stream().anyMatch(r -> r.contains("HTTPS")));
    }
}