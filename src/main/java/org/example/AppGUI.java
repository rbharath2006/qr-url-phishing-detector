package org.example;

import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import java.awt.*;
import java.io.File;
import java.util.List;

public class AppGUI extends JFrame {

    // ---- Cyber theme palette ----
    private static final Color BG = new Color(11, 15, 20);
    private static final Color CARD_BG = new Color(18, 24, 31);
    private static final Color BORDER = new Color(38, 48, 58);
    private static final Color ACCENT = new Color(0, 229, 255);      // cyan
    private static final Color TEXT_MAIN = new Color(220, 228, 232);
    private static final Color TEXT_MUTED = new Color(120, 135, 145);
    private static final Color SAFE = new Color(57, 255, 148);
    private static final Color SUSPICIOUS = new Color(255, 196, 0);
    private static final Color MALICIOUS = new Color(255, 71, 87);

    private static final Font FONT_HEADER = new Font("Consolas", Font.BOLD, 22);
    private static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 13);
    private static final Font FONT_LABEL = new Font("Segoe UI", Font.BOLD, 12);
    private static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);

    private JTextField urlField;
    private JLabel selectedFileLabel;
    private File selectedImageFile;
    private JButton analyzeButton;
    private JPanel verdictBanner;
    private JLabel verdictIcon;
    private JLabel verdictLabel;
    private JLabel scoreLabel;
    private JTextArea reasonsArea;

    private DefaultListModel<HistoryEntry> historyModel;
    private JList<HistoryEntry> historyList;

    public AppGUI() {
        setTitle("QR Phishing Detector");
        setSize(600, 820);
        setMinimumSize(new Dimension(520, 600));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        getContentPane().setBackground(BG);
        setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(BG);
        mainPanel.setBorder(new EmptyBorder(22, 26, 22, 26));

        // ---- Header ----
        JPanel headerRow = new JPanel();
        headerRow.setLayout(new BoxLayout(headerRow, BoxLayout.X_AXIS));
        headerRow.setBackground(BG);
        headerRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        headerRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));

        JLabel shield = new JLabel("\uD83D\uDEE1\uFE0F");
        shield.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 24));

        JLabel title = new JLabel("  QR PHISHING DETECTOR");
        title.setFont(FONT_HEADER);
        title.setForeground(ACCENT);

        headerRow.add(shield);
        headerRow.add(title);
        headerRow.add(Box.createHorizontalGlue());

        JLabel statusDot = new JLabel("\u25CF ENGINE READY");
        statusDot.setFont(new Font("Consolas", Font.PLAIN, 11));
        statusDot.setForeground(SAFE);
        headerRow.add(statusDot);

        JLabel subtitle = new JLabel("Scan QR codes and URLs for phishing indicators before you trust them.");
        subtitle.setFont(FONT_BODY);
        subtitle.setForeground(TEXT_MUTED);
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        subtitle.setBorder(new EmptyBorder(6, 0, 20, 0));

        mainPanel.add(headerRow);
        mainPanel.add(subtitle);

        // ---- Input card ----
        JPanel inputCard = new JPanel();
        inputCard.setLayout(new BoxLayout(inputCard, BoxLayout.Y_AXIS));
        inputCard.setBackground(CARD_BG);
        inputCard.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(1, 1, 1, 1, BORDER),
                new EmptyBorder(18, 18, 18, 18)
        ));
        inputCard.setAlignmentX(Component.LEFT_ALIGNMENT);
        inputCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, 190));

        JLabel urlLabel = new JLabel("TARGET URL");
        urlLabel.setFont(FONT_LABEL);
        urlLabel.setForeground(ACCENT);
        urlLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        urlField = new JTextField();
        urlField.setFont(FONT_MONO);
        urlField.setBackground(new Color(10, 13, 17));
        urlField.setForeground(TEXT_MAIN);
        urlField.setCaretColor(ACCENT);
        urlField.putClientProperty("JTextField.placeholderText", "https://example.com");
        urlField.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(1, 1, 1, 1, BORDER),
                new EmptyBorder(6, 10, 6, 10)
        ));
        urlField.setAlignmentX(Component.LEFT_ALIGNMENT);
        urlField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));

        JPanel orRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        orRow.setBackground(CARD_BG);
        orRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        orRow.setBorder(new EmptyBorder(14, 0, 10, 0));
        JLabel orLabel = new JLabel("— OR —");
        orLabel.setFont(new Font("Consolas", Font.PLAIN, 11));
        orLabel.setForeground(TEXT_MUTED);
        orRow.add(orLabel);

        JPanel filePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        filePanel.setBackground(CARD_BG);
        filePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton uploadButton = new JButton("\uD83D\uDCF7  Upload QR Image");
        styleSecondaryButton(uploadButton);
        selectedFileLabel = new JLabel("No file selected");
        selectedFileLabel.setForeground(TEXT_MUTED);
        selectedFileLabel.setFont(FONT_BODY);
        filePanel.add(uploadButton);
        filePanel.add(selectedFileLabel);

        inputCard.add(urlLabel);
        inputCard.add(Box.createVerticalStrut(6));
        inputCard.add(urlField);
        inputCard.add(orRow);
        inputCard.add(filePanel);

        mainPanel.add(inputCard);
        mainPanel.add(Box.createVerticalStrut(16));

        // ---- Analyze button ----
        analyzeButton = new JButton("\u25B6  ANALYZE");
        analyzeButton.setFont(new Font("Consolas", Font.BOLD, 14));
        analyzeButton.setForeground(new Color(5, 10, 12));
        analyzeButton.setBackground(ACCENT);
        analyzeButton.setFocusPainted(false);
        analyzeButton.setBorder(new EmptyBorder(10, 0, 10, 0));
        analyzeButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        analyzeButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        analyzeButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        mainPanel.add(analyzeButton);
        mainPanel.add(Box.createVerticalStrut(20));

        // ---- Verdict banner ----
        verdictBanner = new JPanel();
        verdictBanner.setLayout(new BoxLayout(verdictBanner, BoxLayout.X_AXIS));
        verdictBanner.setBorder(new EmptyBorder(16, 18, 16, 18));
        verdictBanner.setAlignmentX(Component.LEFT_ALIGNMENT);
        verdictBanner.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        verdictBanner.setVisible(false);

        verdictIcon = new JLabel();
        verdictIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 26));
        verdictIcon.setBorder(new EmptyBorder(0, 0, 0, 14));

        JPanel verdictTextCol = new JPanel();
        verdictTextCol.setOpaque(false);
        verdictTextCol.setLayout(new BoxLayout(verdictTextCol, BoxLayout.Y_AXIS));

        verdictLabel = new JLabel("VERDICT");
        verdictLabel.setFont(new Font("Consolas", Font.BOLD, 18));
        scoreLabel = new JLabel("Risk score");
        scoreLabel.setFont(FONT_MONO);
        scoreLabel.setForeground(TEXT_MUTED);

        verdictTextCol.add(verdictLabel);
        verdictTextCol.add(scoreLabel);

        verdictBanner.add(verdictIcon);
        verdictBanner.add(verdictTextCol);
        mainPanel.add(verdictBanner);
        mainPanel.add(Box.createVerticalStrut(12));

        // ---- Reasons ----
        JLabel reasonsHeader = new JLabel("ANALYSIS DETAILS");
        reasonsHeader.setFont(FONT_LABEL);
        reasonsHeader.setForeground(ACCENT);
        reasonsHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(reasonsHeader);
        mainPanel.add(Box.createVerticalStrut(8));

        reasonsArea = new JTextArea();
        reasonsArea.setEditable(false);
        reasonsArea.setLineWrap(true);
        reasonsArea.setWrapStyleWord(true);
        reasonsArea.setFont(FONT_MONO);
        reasonsArea.setForeground(TEXT_MAIN);
        reasonsArea.setBackground(BG);
        reasonsArea.setBorder(null);
        reasonsArea.setAlignmentX(Component.LEFT_ALIGNMENT);
        reasonsArea.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));
        mainPanel.add(reasonsArea);
        mainPanel.add(Box.createVerticalStrut(20));

        // ---- Scan history ----
        JLabel historyHeader = new JLabel("SCAN HISTORY");
        historyHeader.setFont(FONT_LABEL);
        historyHeader.setForeground(ACCENT);
        historyHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(historyHeader);
        mainPanel.add(Box.createVerticalStrut(8));

        historyModel = new DefaultListModel<>();
        historyList = new JList<>(historyModel);
        historyList.setBackground(CARD_BG);
        historyList.setCellRenderer(new HistoryCellRenderer());
        historyList.setFixedCellHeight(46);
        historyList.setSelectionBackground(new Color(30, 40, 50));
        historyList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && historyList.getSelectedValue() != null) {
                HistoryEntry selected = historyList.getSelectedValue();
                showVerdict(selected.verdict.toUpperCase(), selected.icon, selected.color,
                        selected.url, selected.reasons, selected.score);
            }
        });

        JScrollPane historyScroll = new JScrollPane(historyList);
        historyScroll.setBorder(new MatteBorder(1, 1, 1, 1, BORDER));
        historyScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        historyScroll.setPreferredSize(new Dimension(500, 180));
        historyScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 220));
        mainPanel.add(historyScroll);

        JScrollPane outerScroll = new JScrollPane(mainPanel);
        outerScroll.setBorder(null);
        outerScroll.getViewport().setBackground(BG);
        outerScroll.getVerticalScrollBar().setUnitIncrement(16);
        add(outerScroll, BorderLayout.CENTER);

        // ---- Actions ----
        uploadButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select a QR code image");
            fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                    "Image files", "png", "jpg", "jpeg", "bmp"));
            int returnValue = fileChooser.showOpenDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                selectedImageFile = fileChooser.getSelectedFile();
                selectedFileLabel.setText(selectedImageFile.getName());
                selectedFileLabel.setForeground(ACCENT);
            }
        });

        analyzeButton.addActionListener(e -> handleAnalyze());
        urlField.addActionListener(e -> handleAnalyze());

        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void styleSecondaryButton(JButton b) {
        b.setFont(FONT_BODY);
        b.setForeground(TEXT_MAIN);
        b.setBackground(new Color(26, 33, 41));
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(1, 1, 1, 1, BORDER),
                new EmptyBorder(6, 12, 6, 12)
        ));
        b.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }

    private void handleAnalyze() {
        String typedUrl = urlField.getText().trim();

        if (typedUrl.isEmpty() && selectedImageFile == null) {
            showVerdict("NO INPUT", "\u26A0\uFE0F", TEXT_MUTED, "Please paste a URL or upload a QR image first.", null, -1);
            return;
        }

        analyzeButton.setEnabled(false);
        analyzeButton.setText("\u23F3  SCANNING...");
        reasonsArea.setText("");
        verdictBanner.setVisible(false);

        final String finalTypedUrl = typedUrl;

        SwingWorker<UrlAnalyzer.AnalysisResult, Void> worker = new SwingWorker<>() {
            String resolvedUrl;

            @Override
            protected UrlAnalyzer.AnalysisResult doInBackground() {
                if (!finalTypedUrl.isEmpty()) {
                    resolvedUrl = finalTypedUrl;
                } else {
                    resolvedUrl = Main.decodeQrCode(selectedImageFile.getAbsolutePath());
                }
                if (resolvedUrl == null) return null;
                return UrlAnalyzer.analyze(resolvedUrl);
            }

            @Override
            protected void done() {
                analyzeButton.setEnabled(true);
                analyzeButton.setText("\u25B6  ANALYZE");
                try {
                    UrlAnalyzer.AnalysisResult result = get();
                    if (result == null) {
                        showVerdict("READ ERROR", "\u26A0\uFE0F", TEXT_MUTED,
                                "Could not decode a URL from that image.", null, -1);
                        return;
                    }

                    Color color;
                    String icon;
                    switch (result.verdict) {
                        case "Safe" -> { color = SAFE; icon = "\u2705"; }
                        case "Suspicious" -> { color = SUSPICIOUS; icon = "\u26A0\uFE0F"; }
                        default -> { color = MALICIOUS; icon = "\u26D4"; }
                    }

                    showVerdict(result.verdict.toUpperCase(), icon, color, resolvedUrl, result.reasons, result.score);

                    // Add to history (most recent first)
                    historyModel.add(0, new HistoryEntry(
                            resolvedUrl, result.verdict, icon, color, result.reasons, result.score));

                } catch (Exception ex) {
                    showVerdict("ERROR", "\u26D4", MALICIOUS, ex.getMessage(), null, -1);
                }
            }
        };
        worker.execute();
    }

    private void showVerdict(String verdict, String icon, Color color, String urlOrMessage, List<String> reasons, int score) {
        verdictLabel.setText(verdict);
        verdictLabel.setForeground(color);
        verdictIcon.setText(icon);
        verdictBanner.setBackground(mixWithBg(color, 0.85f));
        verdictBanner.setBorder(BorderFactory.createCompoundBorder(
                new MatteBorder(0, 4, 0, 0, color),
                new EmptyBorder(16, 14, 16, 18)
        ));
        verdictBanner.setVisible(true);

        if (score >= 0) {
            scoreLabel.setText(urlOrMessage + "   |   RISK SCORE: " + score);
        } else {
            scoreLabel.setText(urlOrMessage);
        }

        StringBuilder sb = new StringBuilder();
        if (reasons != null) {
            for (String r : reasons) {
                sb.append("> ").append(r).append("\n");
            }
        }
        reasonsArea.setText(sb.toString());
        revalidate();
        repaint();
    }

    private Color mixWithBg(Color c, float bgRatio) {
        int r = (int) (c.getRed() * (1 - bgRatio) + CARD_BG.getRed() * bgRatio);
        int g = (int) (c.getGreen() * (1 - bgRatio) + CARD_BG.getGreen() * bgRatio);
        int b = (int) (c.getBlue() * (1 - bgRatio) + CARD_BG.getBlue() * bgRatio);
        return new Color(r, g, b);
    }

    // Holds one past scan result, shown in the history list
    private static class HistoryEntry {
        final String url;
        final String verdict;
        final String icon;
        final Color color;
        final List<String> reasons;
        final int score;

        HistoryEntry(String url, String verdict, String icon, Color color, List<String> reasons, int score) {
            this.url = url;
            this.verdict = verdict;
            this.icon = icon;
            this.color = color;
            this.reasons = reasons;
            this.score = score;
        }
    }

    // Renders each history row: icon + verdict on top, URL below, color-coded
    private class HistoryCellRenderer extends JPanel implements ListCellRenderer<HistoryEntry> {
        private final JLabel topLine = new JLabel();
        private final JLabel bottomLine = new JLabel();

        HistoryCellRenderer() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            setBorder(new EmptyBorder(6, 10, 6, 10));
            topLine.setFont(new Font("Consolas", Font.BOLD, 12));
            bottomLine.setFont(FONT_MONO);
            add(topLine);
            add(bottomLine);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends HistoryEntry> list, HistoryEntry entry,
                                                      int index, boolean isSelected, boolean cellHasFocus) {
            topLine.setText(entry.icon + "  " + entry.verdict.toUpperCase() + "   (score " + entry.score + ")");
            topLine.setForeground(entry.color);
            bottomLine.setText(truncate(entry.url, 60));
            bottomLine.setForeground(TEXT_MUTED);
            setBackground(isSelected ? new Color(30, 40, 50) : CARD_BG);
            setOpaque(true);
            return this;
        }

        private String truncate(String s, int max) {
            return s.length() <= max ? s : s.substring(0, max - 3) + "...";
        }
    }

    public static void main(String[] args) {
        FlatDarkLaf.setup();
        SwingUtilities.invokeLater(AppGUI::new);
    }
}