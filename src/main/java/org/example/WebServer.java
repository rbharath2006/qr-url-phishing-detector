package org.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * Embedded web server exposing the existing detection engine (UrlAnalyzer)
 * and QR decoding logic (via ZXing, same as Main.decodeQrCode) through a
 * small HTTP API, with a browser-based HTML/CSS/JS frontend served
 * alongside it. All actual analysis logic is unchanged and untouched —
 * this class only adds a transport layer on top of it.
 *
 * Runs as a background service with a system tray icon (no console window
 * needed once packaged) — right-click the tray icon to reopen the browser
 * or quit the server.
 *
 * Includes basic per-IP rate limiting on the analysis endpoints, since
 * this is designed to eventually run as a public-facing service.
 */
public class WebServer {

    private static final int PORT = 8080;
    private static HttpServer server;

    // ---- Rate limiting ----
    private static final int MAX_REQUESTS_PER_WINDOW = 20;
    private static final long WINDOW_MILLIS = 60_000; // 1 minute
    private static final Map<String, RequestLog> requestLogs = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/", new StaticFileHandler());
        server.createContext("/api/analyze", new AnalyzeUrlHandler());
        server.createContext("/api/analyze-qr", new AnalyzeQrHandler());

        server.setExecutor(Executors.newFixedThreadPool(10)); // handle multiple requests concurrently
        server.start();

        String url = "http://localhost:" + PORT;
        System.out.println("QR Phishing Detector running in background at " + url);

        openBrowser(url);
        setupTrayIcon(url);
    }

    private static void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception e) {
            System.out.println("Could not auto-open browser — open " + url + " manually.");
        }
    }

    /**
     * Adds a system tray icon so the app can run in the background without
     * a visible console/window. Right-click gives "Open" (reopen the
     * browser tab) and "Quit" (stops the server and exits the JVM).
     * If the platform has no system tray support, falls back to just
     * keeping the server running with a console message.
     */
    private static void setupTrayIcon(String url) {
        if (!SystemTray.isSupported()) {
            System.out.println("System tray not supported on this platform — server will keep " +
                    "running in this console window. Close the window to stop it.");
            return;
        }

        try {
            SystemTray tray = SystemTray.getSystemTray();
            BufferedImage icon = createShieldIcon();

            PopupMenu menu = new PopupMenu();

            MenuItem openItem = new MenuItem("Open QR Phishing Detector");
            ActionListener openAction = e -> openBrowser(url);
            openItem.addActionListener(openAction);
            menu.add(openItem);

            menu.addSeparator();

            MenuItem quitItem = new MenuItem("Quit");
            quitItem.addActionListener(e -> {
                server.stop(0);
                tray.remove(activeTrayIcon);
                System.exit(0);
            });
            menu.add(quitItem);

            TrayIcon trayIcon = new TrayIcon(icon, "QR Phishing Detector — running", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(openAction);

            tray.add(trayIcon);
            activeTrayIcon = trayIcon;

        } catch (AWTException e) {
            System.out.println("Could not create system tray icon: " + e.getMessage());
        }
    }

    private static TrayIcon activeTrayIcon;

    private static BufferedImage createShieldIcon() {
        int size = 32;
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        g.setColor(new Color(0, 229, 255));
        int[] xPoints = { size / 2, size - 4, size - 4, size / 2, 4, 4 };
        int[] yPoints = { 2, 8, size - 12, size - 2, size - 12, 8 };
        g.fillPolygon(xPoints, yPoints, xPoints.length);

        g.setColor(new Color(5, 10, 12));
        g.setStroke(new BasicStroke(2));
        g.drawLine(size / 2 - 4, size / 2, size / 2 - 1, size / 2 + 4);
        g.drawLine(size / 2 - 1, size / 2 + 4, size / 2 + 5, size / 2 - 5);

        g.dispose();
        return img;
    }

    // ---- Rate limiting logic ----

    /**
     * Tracks request timestamps for one visitor IP within the current
     * sliding window, so we can count how many requests they've made
     * recently without storing an ever-growing, unbounded history.
     */
    private static class RequestLog {
        final java.util.List<Long> timestamps = new java.util.ArrayList<>();

        synchronized boolean allowAndRecord() {
            long now = System.currentTimeMillis();
            timestamps.removeIf(t -> now - t > WINDOW_MILLIS);
            if (timestamps.size() >= MAX_REQUESTS_PER_WINDOW) {
                return false;
            }
            timestamps.add(now);
            return true;
        }
    }

    /**
     * Returns true if this visitor is still within their allowed request
     * budget for the current window, and records this request against
     * their count. Called at the start of every analysis endpoint.
     */
    private static boolean checkRateLimit(HttpExchange exchange) {
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        RequestLog log = requestLogs.computeIfAbsent(clientIp, k -> new RequestLog());
        return log.allowAndRecord();
    }

    // Serves any file from resources/web/ — index.html for "/", or the
    // requested path otherwise (e.g. "/background_cs.jpg", "/style.css").
    static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String resourcePath = path.equals("/") ? "web/index.html" : "web" + path;

            byte[] bytes;
            try (InputStream is = WebServer.class.getClassLoader().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    respond(exchange, 404, "text/plain", ("Not found: " + resourcePath).getBytes());
                    return;
                }
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                is.transferTo(buffer);
                bytes = buffer.toByteArray();
            }
            respond(exchange, 200, guessContentType(resourcePath), bytes);
        }

        private String guessContentType(String path) {
            if (path.endsWith(".html")) return "text/html; charset=utf-8";
            if (path.endsWith(".css")) return "text/css";
            if (path.endsWith(".js")) return "application/javascript";
            if (path.endsWith(".png")) return "image/png";
            if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
            if (path.endsWith(".gif")) return "image/gif";
            if (path.endsWith(".svg")) return "image/svg+xml";
            return "application/octet-stream";
        }
    }

    // GET /api/analyze?url=<url-encoded string>
    static class AnalyzeUrlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                respond(exchange, 405, "text/plain", "Use GET".getBytes());
                return;
            }

            if (!checkRateLimit(exchange)) {
                respond(exchange, 429, "application/json",
                        errorJson("Too many requests — please wait a moment and try again.").getBytes());
                return;
            }

            Map<String, String> params = parseQuery(exchange.getRequestURI());
            String url = params.get("url");
            if (url == null || url.isBlank()) {
                respond(exchange, 400, "application/json", errorJson("Missing 'url' parameter").getBytes());
                return;
            }

            UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze(url);
            String json = resultToJson(result, null);
            respond(exchange, 200, "application/json", json.getBytes(StandardCharsets.UTF_8));
        }
    }

    // POST /api/analyze-qr  — body is the raw image bytes (frontend sends the File object directly)
    static class AnalyzeQrHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                respond(exchange, 405, "text/plain", "Use POST".getBytes());
                return;
            }

            if (!checkRateLimit(exchange)) {
                respond(exchange, 429, "application/json",
                        errorJson("Too many requests — please wait a moment and try again.").getBytes());
                return;
            }

            byte[] imageBytes;
            try (InputStream is = exchange.getRequestBody()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                is.transferTo(buffer);
                imageBytes = buffer.toByteArray();
            }

            String decodedUrl = decodeQrFromBytes(imageBytes);
            if (decodedUrl == null) {
                respond(exchange, 200, "application/json",
                        errorJson("Could not decode a QR code from that image").getBytes());
                return;
            }

            UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze(decodedUrl);
            String json = resultToJson(result, decodedUrl);
            respond(exchange, 200, "application/json", json.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Decodes a QR code directly from image bytes in memory — same ZXing
     * pipeline as Main.decodeQrCode(), but without needing a file on disk,
     * since the image arrives over HTTP rather than from a local file picker.
     */
    private static String decodeQrFromBytes(byte[] imageBytes) {
        try {
            BufferedImage bufferedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));
            if (bufferedImage == null) return null;

            com.google.zxing.client.j2se.BufferedImageLuminanceSource source =
                    new com.google.zxing.client.j2se.BufferedImageLuminanceSource(bufferedImage);
            com.google.zxing.BinaryBitmap bitmap =
                    new com.google.zxing.BinaryBitmap(new com.google.zxing.common.HybridBinarizer(source));

            com.google.zxing.Result result = new com.google.zxing.MultiFormatReader().decode(bitmap);
            return result.getText();
        } catch (Exception e) {
            return null;
        }
    }

    private static String resultToJson(UrlAnalyzer.AnalysisResult result, String decodedUrl) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"verdict\":\"").append(escape(result.verdict)).append("\",");
        sb.append("\"score\":").append(result.score).append(",");
        if (decodedUrl != null) {
            sb.append("\"decodedUrl\":\"").append(escape(decodedUrl)).append("\",");
        }
        sb.append("\"reasons\":[");
        List<String> reasons = result.reasons;
        for (int i = 0; i < reasons.size(); i++) {
            sb.append("\"").append(escape(reasons.get(i))).append("\"");
            if (i < reasons.size() - 1) sb.append(",");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String errorJson(String message) {
        return "{\"error\":\"" + escape(message) + "\"}";
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> result = new java.util.HashMap<>();
        String query = uri.getRawQuery();
        if (query == null) return result;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                result.put(key, value);
            }
        }
        return result;
    }

    private static void respond(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(status, body.length);
        try (var os = exchange.getResponseBody()) {
            os.write(body);
        }
    }
}