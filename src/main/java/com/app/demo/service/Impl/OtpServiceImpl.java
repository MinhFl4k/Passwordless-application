package com.app.demo.service.Impl;

import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.enums.OtpStatus;
import com.app.demo.model.OtpToken;
import com.app.demo.repository.OtpTokenRepository;
import com.app.demo.service.OtpService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class OtpServiceImpl implements OtpService {

    private final OtpTokenRepository otpTokenRepository;

    private static final int OTP_RESEND_INTERVAL_SECONDS = 60;

    private final PasswordEncoder passwordEncoder;

    public OtpServiceImpl(OtpTokenRepository otpTokenRepository, PasswordEncoder passwordEncoder) {
        this.otpTokenRepository = otpTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String generateOtp(String email) {
        Optional<OtpToken> lastCreatedToken = otpTokenRepository.findTopByEmailOrderByExpiryTimeDesc(email);

        if (lastCreatedToken.isPresent()) {
            OtpToken lastOtp = lastCreatedToken.get();
            LocalDateTime allowedTime = lastOtp.getCreatedAt()
                    .plusSeconds(OTP_RESEND_INTERVAL_SECONDS);
            if (LocalDateTime.now().isBefore(allowedTime)) {
                throw new RuntimeException("Please wait " + OTP_RESEND_INTERVAL_SECONDS + " seconds before sending the OTP again");
            }
        }

        String otp = String.valueOf(new Random().nextInt(900000) + 100000);

        OtpToken token = new OtpToken();
        token.setEmail(email);
        token.setOtp(passwordEncoder.encode(otp));
        token.setCreatedAt(LocalDateTime.now());
        token.setExpiryTime(LocalDateTime.now().plusMinutes(2));
        token.setUsed(false);

        otpTokenRepository.save(token);

        return otp;
    }

    public OtpResponseDto validateOtp(String email, String otp) {
        Optional<OtpToken> tokenOpt =
                otpTokenRepository.findTopByEmailOrderByExpiryTimeDesc(email);

        if (tokenOpt.isEmpty())
            return new OtpResponseDto(OtpStatus.NOT_FOUND);;

        OtpToken token = tokenOpt.get();

        if (token.isUsed())
            return new OtpResponseDto(OtpStatus.USED);
        if (token.getExpiryTime().isBefore(LocalDateTime.now()))
            return new OtpResponseDto(OtpStatus.EXPIRED);;

        boolean otpMatch = passwordEncoder.matches(otp, token.getOtp());
        if (!otpMatch)
            return new OtpResponseDto(OtpStatus.INVALID);;

        token.setUsed(true);
        otpTokenRepository.save(token);

        return new OtpResponseDto(OtpStatus.VALID);
    }
}
