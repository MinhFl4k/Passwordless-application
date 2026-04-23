package com.app.demo.service.Impl;

import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.enums.ErrorMessage;
import com.app.demo.enums.OtpStatus;
import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.TotpLoginService;
import com.app.demo.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class TotpLoginServiceImpl implements TotpLoginService {

    private final UserRepository userRepository;

    @Value("${totp.application.name}")
    private String SECRET;

    @Value("${totp.application.time}")
    private String TIME;

    @Value("${totp.application.url}")
    private String AUTH_SECRET_URL;

    @Override
    public String generateOTPProtocol(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USER_NOT_FOUND.getMessage()));

        String issuer = SECRET;
        String totpSecret = user.getSecret().trim();

        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        String encodedEmail = URLEncoder.encode(email, StandardCharsets.UTF_8);

        return String.format(
                AUTH_SECRET_URL,
                encodedIssuer,
                encodedEmail,
                totpSecret,
                encodedIssuer
        );
    }

    @Override
    public String generateQRCode(String otpProtocol) throws Throwable {
        return TotpUtil.generateQRCode(otpProtocol);
    }

    @Override
    public OtpResponseDto validateTotp(String secret, String totpKey) {

        if (!StringUtils.hasText(secret)) {
            return new OtpResponseDto(OtpStatus.NOT_CONFIGURE);
        }

        if (totpKey == null) {
            return new OtpResponseDto(OtpStatus.NOT_FOUND);
        }

        try {
            if (!TotpUtil.verifyCode(secret, totpKey, Integer.parseInt(TIME))) {
                return new OtpResponseDto(OtpStatus.INVALID);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new InternalAuthenticationServiceException(e.getMessage());
        }

        return new OtpResponseDto(OtpStatus.VALID);
    }
}
