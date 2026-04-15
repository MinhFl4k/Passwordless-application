package com.app.demo.service;

import com.app.demo.model.OneTimeToken;
import jakarta.servlet.http.HttpServletRequest;

public interface LoginWithLinkService {
    void sendLink(String email);

    void loginWithLink(String token, HttpServletRequest request);

    void validateOneTimeToken(OneTimeToken token);
}
