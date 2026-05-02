package com.app.demo.config;

import com.app.demo.auth.common.AccountLockCheckFilter;
import com.app.demo.auth.password.PasswordFailureHandler;
import com.app.demo.auth.password.PasswordSuccessHandler;
import com.app.demo.auth.totp.TotpAuthFilter;
import com.app.demo.auth.totp.TotpAuthProvider;
import com.app.demo.auth.totp.TotpFailureHandler;
import com.app.demo.auth.otp.OtpAuthFilter;
import com.app.demo.auth.otp.OtpAuthProvider;
import com.app.demo.auth.otp.OtpFailureHandler;
import com.app.demo.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableMethodSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailService customUserDetailsService;

    private final OtpAuthProvider otpAuthProvider;

    private final TotpAuthProvider totpAuthProvider;

    private final OtpFailureHandler otpFailureHandler;

    private final TotpFailureHandler totpFailureHandler;

    private final PasswordFailureHandler passwordFailureHandler;

    private final PasswordSuccessHandler passwordSuccessHandler;

    private final AccountLockCheckFilter accountLockCheckFilter;

    private final PasswordEncoder passwordEncoder;

    private final String LOCALHOST = "http://localhost:8080";

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            DaoAuthenticationProvider daoAuthenticationProvider) {
        return new ProviderManager(
                daoAuthenticationProvider,
                otpAuthProvider,
                totpAuthProvider
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {


        OtpAuthFilter otpFilter = new OtpAuthFilter();
        otpFilter.setAuthenticationManager(authenticationManager);
        otpFilter.setFilterProcessesUrl("/otp-login-process");
        otpFilter.setAuthenticationFailureHandler(otpFailureHandler);

        TotpAuthFilter totpFilter = new TotpAuthFilter();
        totpFilter.setAuthenticationManager(authenticationManager);
        totpFilter.setFilterProcessesUrl("/totp-login-process");
        totpFilter.setAuthenticationFailureHandler(totpFailureHandler);

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
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
                        ).permitAll()

                        .requestMatchers(
                                "/edit-profile",
                                "/change-password",
                                "/account-passkey",
                                "/passkeys/delete",
                                "/qrcode/get"
                        ).hasAnyRole("ADMIN", "USER")

                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .accessDeniedPage("/access-denied")
                )
                .addFilterBefore(otpFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(totpFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(accountLockCheckFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(passwordSuccessHandler)
                        .failureHandler(passwordFailureHandler)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/home",true)
                        .failureUrl("/login?error=true")
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                        .permitAll()
                )
                .requestCache(cache -> cache.disable())
                .webAuthn(webAuthn -> webAuthn
                        .rpId("localhost")
                        .allowedOrigins(LOCALHOST)
                )
                .headers(headers -> headers
                        .cacheControl(cache -> {})
                )

                .userDetailsService(customUserDetailsService);

        return http.build();
    }
}
