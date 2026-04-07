package com.app.demo.service.Impl;

import com.app.demo.dto.request.ChangePasswordDTO;
import com.app.demo.dto.request.UserSignupDto;
import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.dto.response.UserResponseDto;
import com.app.demo.enums.AuthProvider;
import com.app.demo.model.User;
import com.app.demo.repository.UserRepository;
import com.app.demo.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public void signupUser(UserSignupDto userSignupDto) throws IllegalArgumentException {

        String email = userSignupDto.getEmail();

        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }

        if(userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("This email is already in use by another user");
        }

        User user = new User();
        user.setName(userSignupDto.getName());
        user.setEmail(email);
        user.setPhone(userSignupDto.getPhone());
        user.setPassword(passwordEncoder.encode(userSignupDto.getPassword()));
        user.setProvider(AuthProvider.LOCAL);

        userRepository.save(user);
    }

    @Override
    public User getUserFromAuthentication(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OAuth2User oauthUser) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            String provider = token.getAuthorizedClientRegistrationId();
            String providerId = oauthUser.getName();
            AuthProvider authProviderEnum = AuthProvider.from(provider);

            return userRepository.findByProviderAndProviderId(authProviderEnum, providerId);

        } else if (authentication.getPrincipal() instanceof UserDetails userDetails) {
            String email = userDetails.getUsername();
            return userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));
        } else {
            throw new RuntimeException("Unsupported authentication type");
        }
    }

    @Override
    public UserResponseDto getUserInfo(Authentication authentication) {
        User user = getUserFromAuthentication(authentication);

        UserResponseDto response = new UserResponseDto();
        response.setId(user.getId());
        response.setName(user.getName());
        response.setEmail(user.getEmail());
        response.setPhone(user.getPhone());

        return response;
    }

    @Override
    public void updateUserInfo(Authentication authentication, UserUpdateDto userDto) {
        User user = getUserFromAuthentication(authentication);

        user.setName(userDto.getName());
        user.setPhone(userDto.getPhone());
        user.setEmail(userDto.getEmail());

        userRepository.save(user);
    }

    @Override
    public UserResponseDto processPostLogin(Authentication authentication)
    {
        User user = new User();

        if (authentication.getPrincipal() instanceof OAuth2User oauthUser) {

            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

            String provider = token.getAuthorizedClientRegistrationId();
            String providerId = oauthUser.getName();

            AuthProvider authProviderEnum = AuthProvider.from(provider);

            user = userRepository.findByProviderAndProviderId(authProviderEnum, providerId);

            if (user == null) {
                user = new User();
                user.setEmail(oauthUser.getAttribute("email"));
                user.setName(oauthUser.getAttribute("name"));
                user.setProviderId(providerId);
                user.setProvider(AuthProvider.from(provider));
                userRepository.save(user);
            }

        } else if (authentication.getPrincipal() instanceof UserDetails userDetails) {
            String email = userDetails.getUsername();
            user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));
        }

        UserResponseDto response = new UserResponseDto();
        response.setId(user.getId());
        response.setName(user.getName());
        response.setEmail(user.getEmail());
        response.setPhone(user.getPhone());
        response.setLocalUser(user.getProvider() == AuthProvider.LOCAL);

        return response;
    }

    @Override
    public void changePassword(String email, ChangePasswordDTO changePasswordDTO)
    {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new RuntimeException("OAuth2 users cannot change password");
        }

        if (!passwordEncoder.matches(changePasswordDTO.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(changePasswordDTO.getNewPassword()));
        userRepository.save(user);
    }

    @Override
    public boolean checkOldPassword(String email, String oldPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return passwordEncoder.matches(oldPassword, user.getPassword());
    }
}
