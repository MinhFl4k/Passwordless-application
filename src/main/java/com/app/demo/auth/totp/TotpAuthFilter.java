package com.app.demo.auth.totp;

import com.app.demo.enums.ErrorMessage;
import com.app.demo.enums.OtpStatus;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.io.IOException;

public class TotpAuthFilter extends UsernamePasswordAuthenticationFilter {

    private static final String POST = "POST";
    private static final String NEW_FLOW = "NEW_FLOW";

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {

        if (!POST.equalsIgnoreCase(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String email;
        HttpSession session = request.getSession();
        Object currentFlow = session.getAttribute("TOTP_LOGIN_FLOW");

        if (NEW_FLOW.equals(currentFlow)) {
            email = request.getSession().getAttribute("TOTP_LOGIN_EMAIL").toString();
        } else {
            email = request.getParameter("email");
        }

        String totpValue = request.getParameter("otp");

        email = (email != null) ? email.trim() : "";
        totpValue = (totpValue != null) ? totpValue.trim() : "";

        if (email.isEmpty()) {
            throw new AuthenticationServiceException(ErrorMessage.EMAIL_REQUIRED.getMessage());
        }

        if (totpValue.isEmpty()) {
            throw new AuthenticationServiceException(OtpStatus.NOT_FOUND.getMessage());
        }

        if (!totpValue.matches("\\d{6}")) {
            throw new AuthenticationServiceException(OtpStatus.INVALID.getMessage());
        }

        TotpAuthToken authRequest =
                new TotpAuthToken(email, totpValue);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

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
            session.removeAttribute("TOTP_LOGIN_EMAIL");
            session.removeAttribute("TOTP_LOGIN_FLOW");
        }

        response.sendRedirect("/home");
    }
}
