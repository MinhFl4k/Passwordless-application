package com.app.demo.service.Impl;

import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.enums.OtpStatus;
import com.app.demo.model.OtpToken;
import com.app.demo.repository.OtpTokenRepository;
import com.app.demo.service.LoginWithOtpService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class LoginWithOtpServiceImpl implements LoginWithOtpService {

    @Autowired
    private OtpTokenRepository otpTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${token.expiration}")
    private long expiration;

    @Transactional
    public String generateOtp(String email) {
        Optional<OtpToken> lastCreatedOtp = otpTokenRepository.findTopByEmailOrderByCreatedAtDesc(email);

        if (lastCreatedOtp.isPresent()) {
            OtpToken lastOtp = lastCreatedOtp.get();
            LocalDateTime allowedTime = lastOtp.getCreatedAt()
                    .plusSeconds(expiration);
            if (LocalDateTime.now().isBefore(allowedTime)) {
                throw new RuntimeException("Please wait " + expiration + " seconds then try again");
            }
        }

        otpTokenRepository.expireAllOldOtp(email);

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
                otpTokenRepository.findTopByEmailOrderByCreatedAtDesc(email);

        if (otp == null || !otp.matches("\\d{6}")) {
            return new OtpResponseDto(OtpStatus.INVALID);
        }

        if (tokenOpt.isEmpty())
            return new OtpResponseDto(OtpStatus.NOT_FOUND);

        OtpToken token = tokenOpt.get();

        if (token.isUsed())
            return new OtpResponseDto(OtpStatus.USED);
        if (token.getExpiryTime().isBefore(LocalDateTime.now()))
            return new OtpResponseDto(OtpStatus.EXPIRED);

        boolean otpMatch = passwordEncoder.matches(otp, token.getOtp());
        if (!otpMatch)
            return new OtpResponseDto(OtpStatus.INVALID);;

        token.setUsed(true);
        otpTokenRepository.save(token);

        return new OtpResponseDto(OtpStatus.VALID);
    }
}
