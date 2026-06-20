package com.example.sqlinjectiondemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        response.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        if (request.isSecure()) {
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "base-uri 'self'; " +
                        "object-src 'none'; " +
                        "frame-ancestors 'none'; " +
                        "form-action 'self'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self' https: data:; " +
                        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net");
        filterChain.doFilter(request, response);
    }
}
