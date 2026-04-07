package com.app.demo.config;

import com.app.demo.dto.custom.CustomUserDetails;
import com.app.demo.enums.AuthProvider;
import com.app.demo.security.OtpAuthenticationFilter;
import com.app.demo.security.OtpAuthenticationProvider;
import com.app.demo.security.OtpFailureHandler;
import com.app.demo.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomUserDetailService customUserDetailsService;

    @Autowired
    private OtpAuthenticationProvider otpAuthenticationProvider;

    @Autowired
    private OtpFailureHandler otpFailureHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        OtpAuthenticationFilter otpFilter = new OtpAuthenticationFilter();
        otpFilter.setAuthenticationManager(authenticationManager);
        otpFilter.setFilterProcessesUrl("/otp-login-process");

        otpFilter.setAuthenticationFailureHandler(otpFailureHandler);

        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/login",
                                "/signup",
                                "/otp-login",
                                "/otp-login-process",
                                "/send-otp",
                                "/css/**",
                                "/js/**"
                        ).permitAll()

                        .requestMatchers("/change-password")
                        .access((auth, context) -> {
                            Object principal = auth.get().getPrincipal();
                            if (principal instanceof CustomUserDetails userDetails) {
                                return new AuthorizationDecision(userDetails.getProvider() == AuthProvider.LOCAL);
                            }
                            return new AuthorizationDecision(false);
                        })

                        .anyRequest().authenticated()
                )
                .authenticationProvider(otpAuthenticationProvider)

                .addFilterBefore(otpFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error=true")
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
                .headers(headers -> headers
                        .cacheControl(cache -> {})
                )

                .userDetailsService(customUserDetailsService);


        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
