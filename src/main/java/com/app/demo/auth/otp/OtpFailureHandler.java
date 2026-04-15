package com.app.demo.auth.otp;

import com.app.demo.enums.OtpStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OtpFailureHandler implements AuthenticationFailureHandler {

    private static final String NEW_FLOW = "NEW_FLOW";

    @Value("${account.locked.error.message}")
    private String ACCOUNT_LOCKED_ERROR_MESSAGE;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException {

        String errorMessage;

        if (exception instanceof LockedException) {
            errorMessage = ACCOUNT_LOCKED_ERROR_MESSAGE;
        } else if (exception instanceof BadCredentialsException) {
            errorMessage = OtpStatus.INVALID.getMessage();
        } else {
            errorMessage = OtpStatus.NOT_FOUND.getMessage();
        }

        HttpSession session = request.getSession();
        session.setAttribute("FLASH_ERROR", errorMessage);

        Object currentFlow = session.getAttribute("OTP_LOGIN_FLOW");

        if (NEW_FLOW.equals(currentFlow)) {
            response.sendRedirect("/new-login-with-otp");
        } else {
            response.sendRedirect("/login-with-otp");
        }
    }
}
