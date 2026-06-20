package com.example.sqlinjectiondemo.model;

import com.example.sqlinjectiondemo.entity.User;

public class AuthResult {

    private final boolean success;
    private final User user;
    private final String queryPreview;
    private final String message;
    private final String mode;
    private final String status;
    private final boolean blocked;

    public AuthResult(boolean success, User user, String queryPreview, String message,
                      String mode, String status, boolean blocked) {
        this.success = success;
        this.user = user;
        this.queryPreview = queryPreview;
        this.message = message;
        this.mode = mode;
        this.status = status;
        this.blocked = blocked;
    }

    public static AuthResult success(User user, String queryPreview, String message, String mode) {
        return new AuthResult(true, user, queryPreview, message, mode, "SUCCESS", false);
    }

    public static AuthResult failed(String queryPreview, String message, String mode) {
        return new AuthResult(false, null, queryPreview, message, mode, "FAILED", false);
    }

    public static AuthResult blocked(String queryPreview, String message, String mode) {
        return new AuthResult(false, null, queryPreview, message, mode, "BLOCKED", true);
    }

    public boolean isSuccess() {
        return success;
    }

    public User getUser() {
        return user;
    }

    public String getQueryPreview() {
        return queryPreview;
    }

    public String getMessage() {
        return message;
    }

    public String getMode() {
        return mode;
    }

    public String getStatus() {
        return status;
    }

    public boolean isBlocked() {
        return blocked;
    }
}
