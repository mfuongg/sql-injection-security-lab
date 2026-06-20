package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.model.CryptoLabResult;
import com.example.sqlinjectiondemo.model.FileScanResult;
import com.example.sqlinjectiondemo.model.QrScanResult;
import com.example.sqlinjectiondemo.model.SecurityFinding;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class SecurityWorkbenchService {

    private static final Set<String> HIGH_RISK_EXTENSIONS = Set.of(
            "exe", "dll", "bat", "cmd", "ps1", "js", "vbs", "jar", "apk", "msi", "scr", "com"
    );
    private static final Pattern IPV4_URL_PATTERN = Pattern.compile("https?://(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?(?:/.*)?");
    private static final Pattern SHORTENER_PATTERN = Pattern.compile("https?://(?:bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|cutt\\.ly|rb\\.gy)/.*");

    public FileScanResult analyzeFile(MultipartFile file) {
        try {
            String fileName = safeName(file.getOriginalFilename());
            String mimeType = file.getContentType() == null ? "application/octet-stream" : file.getContentType();
            byte[] bytes = file.getBytes();
            long size = bytes.length;

            List<SecurityFinding> findings = new ArrayList<>();
            int risk = 0;
            String extension = extensionOf(fileName);

            if (HIGH_RISK_EXTENSIONS.contains(extension)) {
                findings.add(new SecurityFinding("HIGH", "Đuôi tệp thực thi",
                        "Tệp có phần mở rộng thường được dùng để thực thi mã trên máy người dùng."));
                risk += 55;
            }
            if (startsWith(bytes, new byte[]{'M', 'Z'})) {
                findings.add(new SecurityFinding("HIGH", "Mẫu PE/Windows executable",
                        "Phát hiện header MZ, dấu hiệu của tệp thực thi Windows."));
                risk += 35;
            }
            if (size > 5 * 1024 * 1024) {
                findings.add(new SecurityFinding("MEDIUM", "Dung lượng lớn",
                        "Tệp lớn hơn 5 MB, cần kiểm tra thêm trước khi phân phối nội bộ."));
                risk += 10;
            }

            if (isTextLike(extension, mimeType)) {
                String text = new String(bytes, StandardCharsets.UTF_8);
                String lower = text.toLowerCase(Locale.ROOT);
                risk += inspectTextContent(lower, findings);
            }

            if (findings.isEmpty()) {
                findings.add(new SecurityFinding("LOW", "Chưa thấy chỉ báo nổi bật",
                        "Không phát hiện dấu hiệu nguy hiểm rõ ràng theo các heuristic hiện có."));
            }

            int score = clamp(risk);
            return new FileScanResult(
                    fileName,
                    mimeType,
                    size,
                    digestHex(bytes, "SHA-256"),
                    digestHex(bytes, "MD5"),
                    mapRisk(score),
                    score,
                    buildFileSummary(fileName, score, findings),
                    findings
            );
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể phân tích tệp tải lên: " + ex.getMessage(), ex);
        }
    }

    public QrScanResult analyzeQr(MultipartFile file) {
        try {
            String fileName = safeName(file.getOriginalFilename());
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(file.getBytes()));
            if (image == null) {
                throw new IllegalArgumentException("Tệp không phải ảnh hợp lệ hoặc không đọc được.");
            }
            Result result = decodeQr(image);
            String decodedText = result.getText() == null ? "" : result.getText().trim();
            List<SecurityFinding> findings = new ArrayList<>();
            int risk = 0;
            String payloadType = classifyQrPayload(decodedText);

            String lower = decodedText.toLowerCase(Locale.ROOT);
            if (payloadType.equals("URL")) {
                if (lower.startsWith("http://")) {
                    findings.add(new SecurityFinding("MEDIUM", "Liên kết không dùng HTTPS",
                            "QR dẫn tới HTTP thuần, dễ bị can thiệp nội dung trên đường truyền."));
                    risk += 20;
                }
                if (IPV4_URL_PATTERN.matcher(lower).matches()) {
                    findings.add(new SecurityFinding("HIGH", "URL dùng địa chỉ IP trực tiếp",
                            "Đường dẫn không dùng tên miền, thường gặp trong chiến dịch phishing hoặc hạ tầng tạm."));
                    risk += 25;
                }
                if (SHORTENER_PATTERN.matcher(lower).matches()) {
                    findings.add(new SecurityFinding("MEDIUM", "URL rút gọn",
                            "Liên kết rút gọn che khuất đích thực sự, cần mở bằng sandbox trước khi truy cập."));
                    risk += 18;
                }
                if (lower.contains("login") || lower.contains("verify") || lower.contains("password") || lower.contains("bank")) {
                    findings.add(new SecurityFinding("MEDIUM", "Từ khóa nhạy cảm",
                            "Nội dung URL chứa từ khóa thường xuất hiện trong trang đăng nhập hoặc xác minh tài khoản."));
                    risk += 15;
                }
            }
            if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("file:")) {
                findings.add(new SecurityFinding("HIGH", "Scheme bất thường",
                        "QR chứa scheme không an toàn hoặc khó kiểm soát trong môi trường doanh nghiệp."));
                risk += 45;
            }
            if (payloadType.equals("TEXT") && (lower.contains("otp") || lower.contains("password") || lower.contains("seed phrase") || lower.contains("private key"))) {
                findings.add(new SecurityFinding("HIGH", "Nội dung chứa bí mật nhạy cảm",
                        "QR text có dấu hiệu chứa thông tin cần được bảo vệ hoặc không nên chia sẻ công khai."));
                risk += 30;
            }
            if (payloadType.equals("WIFI")) {
                findings.add(new SecurityFinding("MEDIUM", "QR cấu hình Wi‑Fi",
                        "QR có thể tự động cấu hình mạng. Cần xác minh SSID và phương thức mã hóa trước khi dùng."));
                risk += 12;
            }
            if (findings.isEmpty()) {
                findings.add(new SecurityFinding("LOW", "QR hợp lệ",
                        "Đã giải mã được QR và chưa thấy chỉ báo nguy cơ nổi bật."));
            }

            int score = clamp(risk);
            return new QrScanResult(
                    fileName,
                    decodedText,
                    payloadType,
                    mapRisk(score),
                    score,
                    buildQrSummary(payloadType, score, findings),
                    findings
            );
        } catch (NotFoundException ex) {
            throw new IllegalArgumentException("Không tìm thấy mã QR trong ảnh đã tải lên.", ex);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể phân tích QR: " + ex.getMessage(), ex);
        }
    }

    public CryptoLabResult runCrypto(String operation, String inputValue, String secret) {
        try {
            String op = operation == null ? "sha256" : operation.trim().toLowerCase(Locale.ROOT);
            String input = inputValue == null ? "" : inputValue;
            return switch (op) {
                case "sha256" -> new CryptoLabResult("SHA-256", digestHex(input.getBytes(StandardCharsets.UTF_8), "SHA-256"),
                        "Băm một chiều, phù hợp cho fingerprint và kiểm tra toàn vẹn; không dùng để giải mã ngược.");
                case "md5" -> new CryptoLabResult("MD5", digestHex(input.getBytes(StandardCharsets.UTF_8), "MD5"),
                        "MD5 chỉ nên dùng cho nhận diện tệp cũ hoặc so khớp nhanh, không phù hợp cho bảo mật hiện đại.");
                case "base64-encode" -> new CryptoLabResult("Base64 Encode",
                        Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8)),
                        "Base64 chỉ là mã hóa biểu diễn dữ liệu, không phải cơ chế bảo mật.");
                case "base64-decode" -> new CryptoLabResult("Base64 Decode",
                        new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8),
                        "Chuỗi đã được giải mã Base64 về dữ liệu gốc ở dạng UTF-8.");
                case "aes-encrypt" -> new CryptoLabResult("AES/GCM Encrypt", aesEncrypt(input, secret),
                        "AES/GCM cung cấp mã hóa và xác thực toàn vẹn; khóa bí mật cần được quản lý an toàn ngoài mã nguồn.");
                case "aes-decrypt" -> new CryptoLabResult("AES/GCM Decrypt", aesDecrypt(input, secret),
                        "Dữ liệu đã được giải mã bằng cùng passphrase và được kiểm tra tính toàn vẹn qua GCM tag.");
                default -> throw new IllegalArgumentException("Thao tác crypto không hợp lệ.");
            };
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể thực hiện thao tác crypto: " + ex.getMessage(), ex);
        }
    }

    private int inspectTextContent(String lower, List<SecurityFinding> findings) {
        int risk = 0;
        if (lower.contains("powershell") || lower.contains("invoke-webrequest") || lower.contains("cmd.exe")
                || lower.contains("/c start") || lower.contains("wscript") || lower.contains("mshta")) {
            findings.add(new SecurityFinding("HIGH", "Chuỗi thực thi lệnh",
                    "Phát hiện từ khóa thường dùng để tải/khởi chạy payload trên Windows."));
            risk += 35;
        }
        if (lower.contains("drop table") || lower.contains("union select") || lower.contains(" or 1=1")
                || lower.contains("sleep(") || lower.contains("information_schema")) {
            findings.add(new SecurityFinding("HIGH", "Dấu hiệu payload SQL injection",
                    "Tệp văn bản chứa chuỗi truy vấn độc hại hoặc đầu vào mô phỏng tấn công cơ sở dữ liệu."));
            risk += 28;
        }
        if (lower.contains("<script") || lower.contains("javascript:") || lower.contains("eval(") || lower.contains("document.cookie")) {
            findings.add(new SecurityFinding("MEDIUM", "Dấu hiệu script động nguy hiểm",
                    "Tệp có thể chứa script dẫn đến XSS, thực thi mã hoặc đánh cắp phiên làm việc."));
            risk += 22;
        }
        if (lower.contains("-----begin private key-----") || lower.contains("aws_secret_access_key") || lower.contains("api_key")) {
            findings.add(new SecurityFinding("HIGH", "Lộ bí mật hoặc khóa riêng",
                    "Nội dung có thể chứa credential, private key hoặc secret nội bộ."));
            risk += 30;
        }
        return risk;
    }

    private Result decodeQr(BufferedImage image) throws NotFoundException {
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        return new MultiFormatReader().decode(bitmap);
    }

    private String classifyQrPayload(String text) {
        String value = text == null ? "" : text.trim();
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            return "URL";
        }
        if (lower.startsWith("wifi:")) {
            return "WIFI";
        }
        if (lower.startsWith("mailto:")) {
            return "EMAIL";
        }
        if (lower.startsWith("tel:")) {
            return "PHONE";
        }
        return "TEXT";
    }

    private String buildFileSummary(String fileName, int score, List<SecurityFinding> findings) {
        return "Tệp '" + fileName + "' được chấm mức " + mapRisk(score)
                + " với " + findings.size() + " chỉ báo cần lưu ý.";
    }

    private String buildQrSummary(String payloadType, int score, List<SecurityFinding> findings) {
        return "QR loại " + payloadType + " được phân tích với mức " + mapRisk(score)
                + "; tổng cộng " + findings.size() + " phát hiện đã được ghi nhận.";
    }

    private boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes == null || prefix == null || bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private String aesEncrypt(String plainText, String passphrase) throws Exception {
        validatePassphrase(passphrase);
        byte[] salt = randomBytes(16);
        byte[] iv = randomBytes(12);
        SecretKey key = deriveKey(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(cipherText);
    }

    private String aesDecrypt(String bundle, String passphrase) throws Exception {
        validatePassphrase(passphrase);
        String[] parts = bundle == null ? new String[0] : bundle.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Dữ liệu AES phải có định dạng salt:iv:ciphertext (Base64). ");
        }
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] cipherText = Base64.getDecoder().decode(parts[2]);
        SecretKey key = deriveKey(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    private SecretKey deriveKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 65536, 256);
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private void validatePassphrase(String passphrase) {
        if (passphrase == null || passphrase.length() < 8) {
            throw new IllegalArgumentException("Passphrase phải có ít nhất 8 ký tự.");
        }
    }

    private String digestHex(byte[] bytes, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(bytes);
            StringBuilder builder = new StringBuilder();
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Không thể tạo fingerprint: " + ex.getMessage(), ex);
        }
    }

    private boolean isTextLike(String extension, String mimeType) {
        if (mimeType == null) {
            return false;
        }
        return mimeType.startsWith("text/")
                || mimeType.contains("json")
                || mimeType.contains("xml")
                || mimeType.contains("javascript")
                || Set.of("txt", "csv", "json", "xml", "js", "ps1", "bat", "cmd", "sql", "html").contains(extension);
    }

    private String extensionOf(String fileName) {
        int dotIndex = fileName == null ? -1 : fileName.lastIndexOf('.');
        if (dotIndex < 0 || dotIndex == fileName.length() - 1) {
            return "";
        }
        return fileName.substring(dotIndex + 1).toLowerCase(Locale.ROOT);
    }

    private int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    private String mapRisk(int riskScore) {
        if (riskScore >= 85) {
            return "CRITICAL";
        }
        if (riskScore >= 60) {
            return "HIGH";
        }
        if (riskScore >= 30) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private String safeName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return "uploaded-file";
        }
        return fileName.replaceAll("[\\r\\n]", "_").trim();
    }
}
