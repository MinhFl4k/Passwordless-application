package com.app.demo.auth.common;

import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

@Component
@RequiredArgsConstructor
public class AccountLockCheckFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        List<String> prefixes = List.of(
                "/new-login",
                "/new-login-with-otp",
                "/new-login-with-totp",
                "/new-login-with-link",
                "/login",
                "/login-with-link",
                "/login-with-otp",
                "/login-with-totp",
                "/auth/**",
                "/signup",
                "/otp-login-process",
                "/totp-login-process",
                "/send-otp",
                "/account-locked",
                "/account-verified",
                "/access-denied",
                "/css/**",
                "/js/**"
        );
        return prefixes.stream().anyMatch(uri::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {

            String email = authentication.getName();

            User user = userRepository.findByEmail(email).orElse(null);

            boolean locked = user == null
                    || (user.getLockedUntil() != null
                    && user.getLockedUntil().isAfter(LocalDateTime.now()));

            if (locked) {
                new SecurityContextLogoutHandler().logout(request, response, authentication);
                response.sendRedirect(request.getContextPath() + "/account-locked");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
