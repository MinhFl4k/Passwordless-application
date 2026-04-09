package com.app.demo.service;

import com.app.demo.model.OneTimeToken;
import jakarta.servlet.http.HttpServletRequest;

public interface OneTimeLinkService {
    void sendOneTimeLink(String email);

    void loginByOneTimeLink(String token, HttpServletRequest request);

    void validateOneTimeToken(OneTimeToken token);
}
