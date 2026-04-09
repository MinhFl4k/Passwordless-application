package com.app.demo.service;


public interface EmailService {

    void sendOtp(String toEmail, String otp);

    void sendOneTimeLink(String toEmail, String link);
}
