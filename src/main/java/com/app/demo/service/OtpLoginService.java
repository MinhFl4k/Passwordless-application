package com.app.demo.service;

import com.app.demo.dto.response.OtpResponseDto;

public interface OtpLoginService {

    String generateOtp(String email);

    OtpResponseDto validateOtp(String email, String otp);
}
