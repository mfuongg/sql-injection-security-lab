package com.example.sqlinjectiondemo.security;

import com.example.sqlinjectiondemo.model.AuthResult;

public interface AuthenticationStrategy {
    String getMode();
    AuthResult authenticate(String username, String password);
}
