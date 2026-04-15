package com.app.demo.service.Impl;

import com.app.demo.model.OneTimeToken;
import com.app.demo.model.User;
import com.app.demo.repository.OneTimeTokenRepository;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.EmailService;
import com.app.demo.service.JwtService;
import com.app.demo.service.LoginAttemptService;
import com.app.demo.service.LoginWithLinkService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
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
public class LoginWithLinkServiceImpl implements LoginWithLinkService {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OneTimeTokenRepository oneTimeTokenRepository;


    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    @Value("${token.expiration}")
    private long expiration;

    @Transactional
    public void sendLink(String email) {

        Optional<OneTimeToken> lastCreatedToken = oneTimeTokenRepository.findTopByEmailOrderByCreatedAtDesc(email);

        if (lastCreatedToken.isPresent()) {
            OneTimeToken lastToken = lastCreatedToken.get();
            LocalDateTime allowedTime = lastToken.getCreatedAt()
                    .plusSeconds(expiration);
            if (LocalDateTime.now().isBefore(allowedTime)) {
                throw new RuntimeException("Please wait " + expiration + " seconds before sending the link again");
            }
        }

        oneTimeTokenRepository.expireAllOldToken(email);

        String token = jwtService.generateToken(email);

        String link = "http://localhost:8080/auth/link-login-process?token=" + token;

        OneTimeToken oneTimeToken = new OneTimeToken();
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

        OneTimeToken oneTimeToken = oneTimeTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));


        validateOneTimeToken(oneTimeToken);

        String email = jwtService.extractEmail(token);

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        userDetailsChecker.check(userDetails);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

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
    public void validateOneTimeToken(OneTimeToken token) {
        if (token.isUsed() || token.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Invalid token");
        }
    }
}
