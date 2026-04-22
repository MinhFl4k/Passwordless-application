package com.app.demo.service;

import com.app.demo.dto.response.OtpResponseDto;

public interface TotpLoginService {
    String generateOTPProtocol(String email);

    String generateQRCode(String otpProtocol) throws Throwable;

    OtpResponseDto validateTotp(String secret, String totpKey);
}
