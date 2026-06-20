package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.SecurityLog;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.model.SecurityTestCaseItem;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PdfReportService {

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    private static final String FALLBACK_FONT = BaseFont.HELVETICA;
    private static final String CLASSPATH_FONT = "fonts/DejaVuSans.ttf";
    private static final String[] FONT_CANDIDATES = {
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
    };

    private BaseFont cachedBaseFont;

    public byte[] buildSecurityTestReport(DashboardStats stats,
                                          int systemScore,
                                          List<SecurityLog> highRiskEvents,
                                          List<SecurityTestCaseItem> testCases,
                                          int totalPoints) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Document document = new Document(PageSize.A4.rotate(), 32, 32, 28, 28);
            PdfWriter.getInstance(document, outputStream);
            document.open();

            Font titleFont = createFont(18, Font.BOLD, new Color(15, 23, 42));
            Font sectionFont = createFont(12, Font.BOLD, new Color(29, 78, 216));
            Font normalFont = createFont(10, Font.NORMAL, Color.BLACK);
            Font boldFont = createFont(10, Font.BOLD, new Color(15, 23, 42));
            Font smallFont = createFont(9, Font.NORMAL, new Color(51, 65, 85));

            Paragraph title = new Paragraph("BÁO CÁO KIỂM THỬ BẢO MẬT ỨNG DỤNG", titleFont);
            title.setSpacingAfter(6f);
            document.add(title);
            document.add(new Paragraph("Dự án: Hệ thống kiểm thử bảo mật đăng nhập", boldFont));
            document.add(new Paragraph("Thời gian xuất báo cáo: " + LocalDateTime.now().format(TIME_FORMAT), normalFont));
            document.add(new Paragraph("Phạm vi: bảo mật ứng dụng và hệ thống, nhấn mạnh SQL injection, phân quyền, nhật ký kiểm toán và hardening.", normalFont));
            document.add(new Paragraph(" "));

            document.add(new Paragraph("1. TÓM TẮT HỆ THỐNG", sectionFont));
            PdfPTable summaryTable = new PdfPTable(new float[]{2.2f, 1.1f, 2.2f, 1.1f});
            summaryTable.setWidthPercentage(100);
            summaryTable.setSpacingBefore(8f);
            summaryTable.setSpacingAfter(12f);
            addCell(summaryTable, "Điểm hệ thống", boldFont, new Color(239, 246, 255));
            addCell(summaryTable, String.valueOf(systemScore), normalFont, Color.WHITE);
            addCell(summaryTable, "Tổng điểm test cases", boldFont, new Color(239, 246, 255));
            addCell(summaryTable, totalPoints + " điểm", normalFont, Color.WHITE);
            addCell(summaryTable, "Tổng sự kiện", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getTotalLogs()), normalFont, Color.WHITE);
            addCell(summaryTable, "Sự kiện nghi ngờ", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getSuspiciousCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Bypass trên vulnerable", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getVulnerableSuccessCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Fail hoặc block trên secure", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getSecureFailedCount()), normalFont, Color.WHITE);
            document.add(summaryTable);

            document.add(new Paragraph("2. DANH SÁCH RỦI RO ƯU TIÊN", sectionFont));
            if (highRiskEvents == null || highRiskEvents.isEmpty()) {
                document.add(new Paragraph("Hiện chưa có sự kiện rủi ro cao trong nhật ký.", normalFont));
            } else {
                PdfPTable riskTable = new PdfPTable(new float[]{1.8f, 1.6f, 3.0f, 1.0f, 1.0f, 3.2f});
                riskTable.setWidthPercentage(100);
                riskTable.setSpacingBefore(8f);
                riskTable.setSpacingAfter(12f);
                addHeaderCell(riskTable, "Thời gian", smallFont);
                addHeaderCell(riskTable, "Tài khoản", smallFont);
                addHeaderCell(riskTable, "Thông điệp", smallFont);
                addHeaderCell(riskTable, "Chế độ", smallFont);
                addHeaderCell(riskTable, "Rủi ro", smallFont);
                addHeaderCell(riskTable, "Detector", smallFont);
                for (SecurityLog log : highRiskEvents) {
                    addBodyCell(riskTable, formatTime(log.getEventTime()), smallFont);
                    addBodyCell(riskTable, safe(log.getUsernameInput()), smallFont);
                    addBodyCell(riskTable, safe(log.getMessage()), smallFont);
                    addBodyCell(riskTable, safe(log.getLoginMode()), smallFont);
                    addBodyCell(riskTable, safe(log.getRiskLevel()) + " / " + log.getRiskScore(), smallFont);
                    addBodyCell(riskTable, safe(log.getDetectorResult()), smallFont);
                }
                document.add(riskTable);
            }

            document.add(new Paragraph("3. TEST CASES ĐỀ XUẤT CHẤM ĐIỂM", sectionFont));
            PdfPTable caseTable = new PdfPTable(new float[]{0.9f, 2.1f, 2.6f, 2.9f, 0.8f, 1.4f});
            caseTable.setWidthPercentage(100);
            caseTable.setSpacingBefore(8f);
            addHeaderCell(caseTable, "Mã", smallFont);
            addHeaderCell(caseTable, "Hạng mục", smallFont);
            addHeaderCell(caseTable, "Mục tiêu", smallFont);
            addHeaderCell(caseTable, "Kỳ vọng", smallFont);
            addHeaderCell(caseTable, "Điểm", smallFont);
            addHeaderCell(caseTable, "Lớp kiểm soát", smallFont);
            for (SecurityTestCaseItem item : testCases) {
                addBodyCell(caseTable, safe(item.getCode()), smallFont);
                addBodyCell(caseTable, safe(item.getTitle()), smallFont);
                addBodyCell(caseTable, safe(item.getObjective()), smallFont);
                addBodyCell(caseTable, safe(item.getExpectedResult()), smallFont);
                addBodyCell(caseTable, String.valueOf(item.getPoints()), smallFont);
                addBodyCell(caseTable, safe(item.getControlLayer()), smallFont);
            }
            document.add(caseTable);
            document.add(new Paragraph(" "));
            document.add(new Paragraph("4. NHẬN XÉT", sectionFont));
            document.add(new Paragraph("Hệ thống đã bao phủ các lớp: phát hiện đầu vào, xác thực an toàn, khóa tạm thời tài khoản, phân quyền, nhật ký kiểm toán, HTTP security headers và báo cáo PDF.", normalFont));
            document.add(new Paragraph("Phiên bản này ưu tiên hiển thị an toàn hơn: tránh lộ lỗi SQL thô, che dữ liệu mật khẩu thông thường và chuẩn hóa thông báo xác thực.", normalFont));

            document.close();
            return outputStream.toByteArray();
        } catch (DocumentException ex) {
            throw new IllegalStateException("Không thể sinh PDF báo cáo kiểm thử: " + ex.getMessage(), ex);
        }
    }

    public byte[] buildAuditTrailReport(DashboardStats stats,
                                        List<SecurityLog> logs,
                                        List<SecurityLog> highRiskEvents) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Document document = new Document(PageSize.A4.rotate(), 28, 28, 24, 24);
            PdfWriter.getInstance(document, outputStream);
            document.open();

            Font titleFont = createFont(18, Font.BOLD, new Color(15, 23, 42));
            Font sectionFont = createFont(12, Font.BOLD, new Color(29, 78, 216));
            Font normalFont = createFont(10, Font.NORMAL, Color.BLACK);
            Font boldFont = createFont(10, Font.BOLD, new Color(15, 23, 42));
            Font smallFont = createFont(8.5f, Font.NORMAL, new Color(51, 65, 85));

            document.add(new Paragraph("NHẬT KÝ KIỂM TOÁN BẢO MẬT", titleFont));
            document.add(new Paragraph("Thời gian xuất: " + LocalDateTime.now().format(TIME_FORMAT), normalFont));
            document.add(new Paragraph("Mục tiêu: phục vụ hậu kiểm các sự kiện bảo mật, tập trung vào risk score, detector summary và trạng thái xác thực.", normalFont));
            document.add(new Paragraph(" "));

            document.add(new Paragraph("1. TỔNG QUAN CHỈ SỐ BẢO MẬT", sectionFont));
            PdfPTable summaryTable = new PdfPTable(new float[]{2.0f, 1.0f, 2.0f, 1.0f});
            summaryTable.setWidthPercentage(100);
            summaryTable.setSpacingBefore(8f);
            summaryTable.setSpacingAfter(12f);
            addCell(summaryTable, "Tổng sự kiện", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getTotalLogs()), normalFont, Color.WHITE);
            addCell(summaryTable, "Sự kiện nghi ngờ", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getSuspiciousCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Thành công", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getSuccessCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Thất bại", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getFailedCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Bị chặn", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getBlockedCount()), normalFont, Color.WHITE);
            addCell(summaryTable, "Bypass trên vulnerable", boldFont, new Color(248, 250, 252));
            addCell(summaryTable, String.valueOf(stats.getVulnerableSuccessCount()), normalFont, Color.WHITE);
            document.add(summaryTable);

            document.add(new Paragraph("2. SỰ KIỆN RỦI RO CAO", sectionFont));
            if (highRiskEvents == null || highRiskEvents.isEmpty()) {
                document.add(new Paragraph("Chưa có sự kiện rủi ro cao.", normalFont));
            } else {
                PdfPTable highRiskTable = new PdfPTable(new float[]{1.6f, 1.4f, 2.8f, 0.9f, 1.1f, 2.8f});
                highRiskTable.setWidthPercentage(100);
                highRiskTable.setSpacingBefore(8f);
                highRiskTable.setSpacingAfter(12f);
                addHeaderCell(highRiskTable, "Thời gian", smallFont);
                addHeaderCell(highRiskTable, "Tài khoản", smallFont);
                addHeaderCell(highRiskTable, "Thông điệp", smallFont);
                addHeaderCell(highRiskTable, "Chế độ", smallFont);
                addHeaderCell(highRiskTable, "Rủi ro", smallFont);
                addHeaderCell(highRiskTable, "Detector", smallFont);
                for (SecurityLog log : highRiskEvents) {
                    addBodyCell(highRiskTable, formatTime(log.getEventTime()), smallFont);
                    addBodyCell(highRiskTable, safe(log.getUsernameInput()), smallFont);
                    addBodyCell(highRiskTable, safe(log.getMessage()), smallFont);
                    addBodyCell(highRiskTable, safe(log.getLoginMode()), smallFont);
                    addBodyCell(highRiskTable, safe(log.getRiskLevel()) + " / " + log.getRiskScore(), smallFont);
                    addBodyCell(highRiskTable, safe(log.getDetectorResult()), smallFont);
                }
                document.add(highRiskTable);
            }

            document.add(new Paragraph("3. BẢNG GHI SỰ KIỆN", sectionFont));
            PdfPTable ledgerTable = new PdfPTable(new float[]{1.5f, 1.1f, 1.0f, 1.0f, 0.9f, 0.9f, 2.6f});
            ledgerTable.setWidthPercentage(100);
            ledgerTable.setSpacingBefore(8f);
            addHeaderCell(ledgerTable, "Thời gian", smallFont);
            addHeaderCell(ledgerTable, "IP", smallFont);
            addHeaderCell(ledgerTable, "User", smallFont);
            addHeaderCell(ledgerTable, "Chế độ", smallFont);
            addHeaderCell(ledgerTable, "Rủi ro", smallFont);
            addHeaderCell(ledgerTable, "Trạng thái", smallFont);
            addHeaderCell(ledgerTable, "Detector", smallFont);
            List<SecurityLog> limitedLogs = logs == null ? List.of() : logs.stream().limit(40).toList();
            for (SecurityLog log : limitedLogs) {
                addBodyCell(ledgerTable, formatTime(log.getEventTime()), smallFont);
                addBodyCell(ledgerTable, safe(log.getIpAddress()), smallFont);
                addBodyCell(ledgerTable, safe(log.getUsernameInput()), smallFont);
                addBodyCell(ledgerTable, safe(log.getLoginMode()), smallFont);
                addBodyCell(ledgerTable, safe(log.getRiskLevel()) + " / " + log.getRiskScore(), smallFont);
                addBodyCell(ledgerTable, safe(log.getStatus()), smallFont);
                addBodyCell(ledgerTable, safe(log.getDetectorResult()), smallFont);
            }
            document.add(ledgerTable);

            document.close();
            return outputStream.toByteArray();
        } catch (DocumentException ex) {
            throw new IllegalStateException("Không thể sinh PDF audit trail: " + ex.getMessage(), ex);
        }
    }

    private void addCell(PdfPTable table, String text, Font font, Color background) {
        PdfPCell cell = new PdfPCell(new Phrase(safe(text), font));
        cell.setBackgroundColor(background);
        cell.setBorderColor(new Color(226, 232, 240));
        cell.setPadding(8f);
        table.addCell(cell);
    }

    private void addHeaderCell(PdfPTable table, String text, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(safe(text), createFont(font.getSize(), Font.BOLD, Color.WHITE)));
        cell.setBackgroundColor(new Color(15, 23, 42));
        cell.setBorder(Rectangle.NO_BORDER);
        cell.setPadding(8f);
        table.addCell(cell);
    }

    private void addBodyCell(PdfPTable table, String text, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(safe(text), font));
        cell.setBackgroundColor(Color.WHITE);
        cell.setBorderColor(new Color(226, 232, 240));
        cell.setPadding(7f);
        table.addCell(cell);
    }

    private Font createFont(float size, int style, Color color) {
        try {
            BaseFont baseFont = resolveBaseFont();
            Font font = new Font(baseFont, size, style, color);
            font.setColor(color);
            return font;
        } catch (DocumentException | IOException ex) {
            Font fallback = new Font(Font.HELVETICA, size, style, color);
            fallback.setColor(color);
            return fallback;
        }
    }

    private synchronized BaseFont resolveBaseFont() throws DocumentException, IOException {
        if (cachedBaseFont != null) {
            return cachedBaseFont;
        }

        ClassPathResource resource = new ClassPathResource(CLASSPATH_FONT);
        if (resource.exists()) {
            try (InputStream inputStream = resource.getInputStream()) {
                byte[] fontBytes = inputStream.readAllBytes();
                cachedBaseFont = BaseFont.createFont(CLASSPATH_FONT, BaseFont.IDENTITY_H, BaseFont.EMBEDDED, false, fontBytes, null);
                return cachedBaseFont;
            }
        }

        for (String candidate : FONT_CANDIDATES) {
            if (Files.exists(Path.of(candidate))) {
                cachedBaseFont = BaseFont.createFont(candidate, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                return cachedBaseFont;
            }
        }

        cachedBaseFont = BaseFont.createFont(FALLBACK_FONT, BaseFont.WINANSI, BaseFont.NOT_EMBEDDED);
        return cachedBaseFont;
    }

    private String formatTime(LocalDateTime value) {
        return value == null ? "N/A" : value.format(TIME_FORMAT);
    }

    private String safe(String value) {
        if (value == null || value.isBlank()) {
            return "N/A";
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        if (normalized.length() <= 220) {
            return normalized;
        }
        return normalized.substring(0, 217) + "...";
    }
}
