package com.example.sqlinjectiondemo.service;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class CsrfService {

    private static final String SESSION_KEY = "csrfToken";

    public String ensureToken(HttpSession session) {
        Object current = session.getAttribute(SESSION_KEY);
        if (current instanceof String token && !token.isBlank()) {
            return token;
        }
        String token = UUID.randomUUID().toString();
        session.setAttribute(SESSION_KEY, token);
        return token;
    }

    public boolean isValid(HttpSession session, String submittedToken) {
        Object current = session.getAttribute(SESSION_KEY);
        return current instanceof String token
                && submittedToken != null
                && !submittedToken.isBlank()
                && token.equals(submittedToken);
    }
}
