package com.app.demo.service;

import com.app.demo.dto.request.ChangePasswordDTO;
import com.app.demo.dto.request.UserSignupDto;
import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.dto.response.UserResponseDto;
import com.app.demo.model.User;
import org.springframework.security.core.Authentication;

public interface UserService {
    void signupUser(
            UserSignupDto userSignupDto
    ) throws IllegalArgumentException;

    UserResponseDto processPostLogin(
            Authentication authentication
    );

    User getUserFromAuthentication(
            Authentication authentication
    );

    UserResponseDto getUserInfo(
            Authentication authentication
    );

    User findByEmail(String email);

    void updateUserInfo(
            Authentication authentication,
            UserUpdateDto userDto
    );

    void changePassword(
            String email,
            ChangePasswordDTO changePasswordDTO
    );

    boolean checkOldPassword(
            String email,
            String oldPassword
    );

    void onOtpFailure(User user);

    void onOtpSuccess(User user);

    boolean isLocked(User user);
}
