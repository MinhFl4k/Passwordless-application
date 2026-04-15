package com.app.demo.auth.passwords;

import com.app.demo.repository.UserRepository;
import com.app.demo.service.LoginAttemptService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class PasswordSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    public PasswordSuccessHandler(UserRepository userRepository,
                                  LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String email = authentication.getName();

        userRepository.findByEmail(email).ifPresent(loginAttemptService::onLoginSuccess);

        response.sendRedirect("/home");
    }
}
