package com.app.demo.service;


import com.app.demo.enums.UserTokenType;

public interface EmailService {

    void sendOtp(String toEmail, String otp);

    void sendUserTokenLink(String toEmail, String link, UserTokenType userTokenType);
}
