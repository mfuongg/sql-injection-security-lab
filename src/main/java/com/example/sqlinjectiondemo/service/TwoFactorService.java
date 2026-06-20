package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.model.TwoFactorVerificationResult;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class TwoFactorService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int DEFAULT_WINDOW = 1;
    private static final int DIGITS = 6;
    private static final long PERIOD_SECONDS = 30L;
    private static final String ISSUER = "Security Operations Center";

    public String generateSecret() {
        byte[] random = new byte[20];
        new SecureRandom().nextBytes(random);
        return encodeBase32(random);
    }

    public String buildOtpAuthUrl(String username, String secret) {
        String label = urlEncode(ISSUER + ":" + username);
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + urlEncode(ISSUER) + "&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
    }

    public String buildQrDataUrl(String username, String secret) {
        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(buildOtpAuthUrl(username, secret), BarcodeFormat.QR_CODE, 220, 220);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", outputStream);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể tạo QR 2FA.", ex);
        }
    }

    public TwoFactorVerificationResult verifyCode(String secret, String submittedCode, Long lastUsedCounter) {
        if (secret == null || secret.isBlank() || submittedCode == null || !submittedCode.matches("\\d{6}")) {
            return new TwoFactorVerificationResult(false, -1);
        }
        long currentCounter = System.currentTimeMillis() / 1000L / PERIOD_SECONDS;
        long floor = lastUsedCounter == null ? Long.MIN_VALUE : lastUsedCounter;
        for (int offset = -DEFAULT_WINDOW; offset <= DEFAULT_WINDOW; offset++) {
            long counter = currentCounter + offset;
            if (counter <= floor) {
                continue;
            }
            String expected = generateCode(secret, counter);
            if (submittedCode.equals(expected)) {
                return new TwoFactorVerificationResult(true, counter);
            }
        }
        return new TwoFactorVerificationResult(false, -1);
    }

    private String generateCode(String secret, long counter) {
        try {
            byte[] key = decodeBase32(secret);
            byte[] data = new byte[8];
            long value = counter;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % 1_000_000;
            return String.format("%06d", otp);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể xác minh mã 2FA.", ex);
        }
    }

    private String encodeBase32(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        int current = 0;
        int bits = 0;
        for (byte b : bytes) {
            current = (current << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                builder.append(BASE32_ALPHABET.charAt((current >> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            builder.append(BASE32_ALPHABET.charAt((current << (5 - bits)) & 0x1F));
        }
        return builder.toString();
    }

    private byte[] decodeBase32(String value) {
        String normalized = value.replace("=", "").replace(" ", "").toUpperCase();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int current = 0;
        int bits = 0;
        for (char c : normalized.toCharArray()) {
            int index = BASE32_ALPHABET.indexOf(c);
            if (index < 0) {
                throw new IllegalArgumentException("Secret 2FA không hợp lệ.");
            }
            current = (current << 5) | index;
            bits += 5;
            if (bits >= 8) {
                outputStream.write((current >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return outputStream.toByteArray();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
