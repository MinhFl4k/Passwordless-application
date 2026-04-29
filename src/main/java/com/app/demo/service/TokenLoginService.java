package com.app.demo.service;

import com.app.demo.dto.common.CustomUserDetails;
import com.app.demo.enums.UserTokenType;
import jakarta.servlet.http.HttpServletRequest;

public interface TokenLoginService {

    void sendUserTokenLink(String email, UserTokenType userTokenType);

    void loginWithUserToken(String token, HttpServletRequest request);

    void verifyWithUserToken(String token, HttpServletRequest request);

    CustomUserDetails validateUserToken(String token);
}
