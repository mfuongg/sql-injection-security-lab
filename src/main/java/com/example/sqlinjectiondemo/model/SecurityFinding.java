package com.example.sqlinjectiondemo.model;

public class SecurityFinding {

    private final String severity;
    private final String title;
    private final String detail;

    public SecurityFinding(String severity, String title, String detail) {
        this.severity = severity;
        this.title = title;
        this.detail = detail;
    }

    public String getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }
}
