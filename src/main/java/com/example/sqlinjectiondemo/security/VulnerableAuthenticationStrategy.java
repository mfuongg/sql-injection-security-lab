package com.example.sqlinjectiondemo.security;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.AuthResult;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

@Component
public class VulnerableAuthenticationStrategy implements AuthenticationStrategy {

    private final DataSource dataSource;

    public VulnerableAuthenticationStrategy(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public String getMode() {
        return "VULNERABLE";
    }

    @Override
    public AuthResult authenticate(String username, String password) {
        String sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "' AND enabled=true";

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {

            if (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getLong("id"));
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                user.setPasswordHash(resultSet.getString("password_hash"));
                user.setRole(resultSet.getString("role"));
                user.setEnabled(resultSet.getBoolean("enabled"));
                user.setFailedAttempts(resultSet.getInt("failed_attempts"));
                return AuthResult.success(user, sql,
                        "Xác thực thành công trên luồng vulnerable.",
                        getMode());
            }
            return AuthResult.failed(sql, "Xác thực thất bại trên luồng vulnerable.", getMode());
        } catch (Exception ex) {
            return AuthResult.failed(sql, "Luồng vulnerable phát sinh lỗi truy vấn: " + ex.getMessage(), getMode());
        }
    }
}
