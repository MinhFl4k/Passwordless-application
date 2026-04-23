package com.app.demo.auth.password;

import com.app.demo.enums.ErrorMessage;
import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.LoginAttemptService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class PasswordFailureHandler implements AuthenticationFailureHandler {

    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    public PasswordFailureHandler(UserRepository userRepository,
                                  LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        HttpSession session = request.getSession();
        String email = request.getParameter("username");

        if (exception instanceof LockedException) {
            session.setAttribute("FLASH_ERROR", ErrorMessage.ACCOUNT_LOCKED.getMessage());
            response.sendRedirect("/login");
            return;
        }

        if (email != null && !email.isBlank()) {
            Optional<User> optionalUser = userRepository.findByEmail(email.trim());

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                loginAttemptService.onPasswordFailure(user);

                if (loginAttemptService.isLocked(user)) {
                    session.setAttribute("FLASH_ERROR", ErrorMessage.ACCOUNT_LOCKED.getMessage());
                    response.sendRedirect("/login");
                    return;
                }
            }
        }

        if (exception instanceof BadCredentialsException) {
            session.setAttribute("FLASH_ERROR", "Invalid email or password.");
        } else {
            session.setAttribute("FLASH_ERROR", "Login failed");
        }

        response.sendRedirect("/login");
    }
}