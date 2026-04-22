package com.app.demo.auth.totp;

import com.app.demo.dto.common.CustomUserDetails;
import com.app.demo.dto.response.OtpResponseDto;
import com.app.demo.enums.ErrorMessage;
import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.LoginAttemptService;
import com.app.demo.service.TotpLoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
public class TotpAuthProvider implements AuthenticationProvider {

    private final TotpLoginService totpService;

    private final UserDetailsService userDetailsService;

    private final LoginAttemptService loginAttemptService;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = (String) authentication.getPrincipal();
        String totp = authentication.getCredentials().toString();

        CustomUserDetails userDetails =
                (CustomUserDetails) userDetailsService.loadUserByUsername(email);
        userDetailsChecker.check(userDetails);
        User user = userDetails.getUser();
        String secret = user.getSecret();

        OtpResponseDto result = totpService.validateTotp(secret, totp);

        if (!result.isValid()) {
            loginAttemptService.onOtpFailure(user);

            if (loginAttemptService.isLocked(user)) {
                throw new LockedException(ErrorMessage.ACCOUNT_LOCKED.getMessage());
            }
            throw new BadCredentialsException(result.getMessage());
        }
        loginAttemptService.onLoginSuccess(user);

        TotpAuthToken authenticatedToken = new TotpAuthToken(userDetails, null, userDetails.getAuthorities());
        authenticatedToken.eraseCredentials();

        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TotpAuthToken.class.isAssignableFrom(authentication);
    }
}
