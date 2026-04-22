package com.app.demo.auth.otp;

import com.app.demo.enums.ErrorMessage;
import com.app.demo.enums.OtpStatus;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.io.IOException;

public class OtpAuthFilter extends UsernamePasswordAuthenticationFilter {

    private static final String POST = "POST";

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {

        if (!request.getMethod().equals(POST)) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String otp = request.getParameter("otp");
        String email = request.getSession().getAttribute("OTP_LOGIN_EMAIL").toString();

        email = (email != null) ? email.trim() : "";
        otp = (otp != null) ? otp.trim() : "";

        if (email.isEmpty()) {
            throw new AuthenticationServiceException(ErrorMessage.USER_NOT_FOUND.getMessage());
        } else if (otp.isEmpty()) {
            throw new AuthenticationServiceException(OtpStatus.NOT_FOUND.getMessage());
        }

        OtpAuthToken authRequest =
                new OtpAuthToken(email, otp);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);

        HttpSessionSecurityContextRepository securityContextRepository =
                new HttpSessionSecurityContextRepository();
        securityContextRepository.saveContext(context, request, response);

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute("OTP_LOGIN_EMAIL");
            session.removeAttribute("OTP_LOGIN_FLOW");
        }

        response.sendRedirect("/home");
    }
}
