package com.app.demo.service;

import com.app.demo.model.LoginToken;
import jakarta.servlet.http.HttpServletRequest;

public interface MagicLinkLoginService {
    void sendLink(String email);

    void loginWithLink(String token, HttpServletRequest request);

    void validateOneTimeToken(LoginToken token);
}
