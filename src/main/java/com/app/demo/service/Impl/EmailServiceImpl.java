package com.app.demo.service.Impl;

import com.app.demo.enums.UserTokenType;
import com.app.demo.service.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendOtp(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Your login code");
        message.setText("Your login code is: " + otp);

        mailSender.send(message);
    }

    @Override
    public void sendUserTokenLink(String toEmail, String link, UserTokenType userTokenType) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject(userTokenType.getSubject());
        message.setText(userTokenType.getMessage() + link);

        mailSender.send(message);
    }
}
