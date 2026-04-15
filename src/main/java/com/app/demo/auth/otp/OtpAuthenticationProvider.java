package com.app.demo.auth.otp;

import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.LoginAttemptService;
import com.app.demo.service.LoginWithOtpService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;


@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final LoginWithOtpService loginWithOtpService;

    private final UserDetailsService userDetailsService;

    private final UserRepository userRepository;

    private final LoginAttemptService loginAttemptService;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    @Value("${account.locked.error.message}")
    private String ACCOUNT_LOCKED_ERROR_MESSAGE;

    public OtpAuthenticationProvider(
            LoginWithOtpService loginWithOtpService,
            UserDetailsService userDetailsService,
            UserRepository userRepository,
            LoginAttemptService loginAttemptService) {
        this.loginWithOtpService = loginWithOtpService;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        String email = authentication.getName();
        String otp = authentication.getCredentials().toString();

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        userDetailsChecker.check(userDetails);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("USER_NOT_FOUND"));

        OtpResponseDto result = loginWithOtpService.validateOtp(email, otp);

        if (!result.isValid()) {
            loginAttemptService.onOtpFailure(user);

            if (loginAttemptService.isLocked(user)) {
                throw new LockedException(ACCOUNT_LOCKED_ERROR_MESSAGE);
            }

            throw new BadCredentialsException(result.getMessage());
        }

        loginAttemptService.onLoginSuccess(user);

        OtpAuthenticationToken authenticatedToken =
                new OtpAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authenticatedToken.eraseCredentials();

        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
