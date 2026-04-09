package com.app.demo.auth;

import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.service.OtpService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;


@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final OtpService otpService;

    private final UserDetailsService userDetailsService;

    public OtpAuthenticationProvider(OtpService otpService, UserDetailsService userDetailsService) {
        this.otpService = otpService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        String email = authentication.getName();
        String otp = authentication.getCredentials().toString();

        OtpResponseDto result = otpService.validateOtp(email, otp);

        if (!result.isValid()) {
            throw new BadCredentialsException(result.getMessage());
        }

        try {
            UserDetails user = userDetailsService.loadUserByUsername(email);

            return new OtpAuthenticationToken(
                    user,
                    otp,
                    user.getAuthorities()
            );
        } catch (UsernameNotFoundException ex) {
            throw new BadCredentialsException("USER_NOT_FOUND");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
