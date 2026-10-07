package org.example;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("QR Phishing Detector");
        System.out.println("1. Upload a QR code image");
        System.out.println("2. Paste a URL directly");
        System.out.print("Choose an option (1 or 2): ");

        String choice = scanner.nextLine().trim();
        String candidateUrl = null;

        if (choice.equals("1")) {
            System.out.print("Enter the full path to the QR image file: ");
            String imagePath = scanner.nextLine().trim();
            candidateUrl = decodeQrCode(imagePath);

            if (candidateUrl == null) {
                System.out.println("Could not extract a URL from that image. Exiting.");
                return;
            }

        } else if (choice.equals("2")) {
            System.out.print("Enter the URL to check: ");
            candidateUrl = scanner.nextLine().trim();

        } else {
            System.out.println("Invalid choice. Exiting.");
            return;
        }

        System.out.println("\nCandidate URL: " + candidateUrl);

        UrlAnalyzer.AnalysisResult result = UrlAnalyzer.analyze(candidateUrl);

        System.out.println("Verdict: " + result.verdict + " (risk score: " + result.score + ")");
        System.out.println("Reasons:");
        for (String reason : result.reasons) {
            System.out.println(" - " + reason);
        }
    }

    public static String decodeQrCode(String imagePath) {
        try {
            BufferedImage bufferedImage = ImageIO.read(new File(imagePath));

            if (bufferedImage == null) {
                System.out.println("Failed to load image. Check the file path.");
                return null;
            }

            BufferedImageLuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

            Result result = new MultiFormatReader().decode(bitmap);
            return result.getText();

        } catch (Exception e) {
            System.out.println("Error decoding QR code: " + e.getMessage());
            return null;
        }
    }
}