package com.app.demo.service.Impl;

import com.app.demo.enums.ErrorMessage;
import com.app.demo.model.LoginToken;
import com.app.demo.model.User;
import com.app.demo.repository.LoginTokenRepository;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.EmailService;
import com.app.demo.service.JwtService;
import com.app.demo.service.LoginAttemptService;
import com.app.demo.service.MagicLinkLoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MagicLinkLoginServiceImpl implements MagicLinkLoginService {

    private final JwtService jwtService;

    private final EmailService emailService;

    private final UserDetailsService userDetailsService;

    private final LoginAttemptService loginAttemptService;

    private final UserRepository userRepository;

    private final LoginTokenRepository oneTimeTokenRepository;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    private final String MAGIC_LINK = "http://localhost:8080/auth/link-login-process?token=";

    @Value("${token.expiration}")
    private long expiration;

    @Transactional
    public void sendLink(String email) {

        Optional<LoginToken> lastCreatedToken = oneTimeTokenRepository.findTopByEmailOrderByCreatedAtDesc(email);

        if (lastCreatedToken.isPresent()) {
            LoginToken lastToken = lastCreatedToken.get();
            LocalDateTime allowedTime = lastToken.getCreatedAt()
                    .plusSeconds(expiration);
            if (LocalDateTime.now().isBefore(allowedTime)) {
                throw new RuntimeException("Please wait " + expiration + " seconds before sending the link again");
            }
        }

        oneTimeTokenRepository.expireAllOldToken(email);

        String token = jwtService.generateToken(email);

        String link = MAGIC_LINK + token;

        LoginToken oneTimeToken = new LoginToken();
        oneTimeToken.setEmail(email);
        oneTimeToken.setToken(token);
        oneTimeToken.setCreatedAt(LocalDateTime.now());
        oneTimeToken.setExpiryTime(LocalDateTime.now().plusMinutes(2));
        oneTimeToken.setUsed(false);

        oneTimeTokenRepository.save(oneTimeToken);

        emailService.sendOneTimeLink(email, link);
    }

    @Override
    public void loginWithLink(String token, HttpServletRequest request) {
        if (token == null || !jwtService.isValid(token)) {
            throw new RuntimeException("Invalid token");
        }

        LoginToken oneTimeToken = oneTimeTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));


        validateOneTimeToken(oneTimeToken);

        String email = jwtService.extractEmail(token);

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        userDetailsChecker.check(userDetails);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException(ErrorMessage.USER_NOT_FOUND.getMessage()));

        oneTimeToken.setUsed(true);
        oneTimeTokenRepository.save(oneTimeToken);

        loginAttemptService.onLoginSuccess(user);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        HttpSession session = request.getSession(true);
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                context
        );
    }

    @Override
    public void validateOneTimeToken(LoginToken token) {
        if (token.isUsed() || token.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Invalid token");
        }
    }
}
