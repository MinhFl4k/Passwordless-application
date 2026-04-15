package com.app.demo.controller;

import com.app.demo.dto.request.ChangePasswordDTO;
import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.dto.response.UserResponseDto;
import com.app.demo.service.JwtService;
import com.app.demo.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;

@Controller
public class UserController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        UserResponseDto userResponseDto = userService.processPostLogin(authentication);

        model.addAttribute("needUpdateEmail",
                userResponseDto.getEmail() == null || userResponseDto.getEmail().isEmpty());

        model.addAttribute("needUpdatePhone",
                userResponseDto.getPhone() == null || userResponseDto.getPhone().isEmpty());

        model.addAttribute("user", userResponseDto);
        return "home";
    }

    @GetMapping("/edit-profile")
    public String showEditPage(Authentication authentication, Model model) {
        UserResponseDto userResponseDto = userService.getUserInfo(authentication);
        model.addAttribute("user", userResponseDto);
        return "edit";
    }

    @PostMapping("/edit-profile")
    public String updateProfile(
            @Valid @ModelAttribute("user") UserUpdateDto userDto,
            BindingResult result,
            Authentication authentication) {
        if (result.hasErrors()) {
            return "edit";
        }
        try {
            userService.updateUserInfo(authentication, userDto);
        } catch (RuntimeException e) {
            System.err.println("Update profile failed: " + e.getMessage());
        }

        return "redirect:/home";
    }

    @GetMapping("/change-password")
    public String showChangePasswordPage(Model model) {
        model.addAttribute("passwordDto", new ChangePasswordDTO());
        return "change-password";
    }

    @PostMapping("/change-password")
    public String changePassword(
            @Valid @ModelAttribute("passwordDto") ChangePasswordDTO changePasswordDTO,
            BindingResult result,
            Principal principal
    ) {
        if (result.hasErrors()) {
            return "change-password";
        }

        String email = principal.getName();
        try {
            userService.changePassword(email, changePasswordDTO);
        } catch (RuntimeException e) {
            System.err.println("Change password failed: " + e.getMessage());
        }

        return "redirect:/home";
    }
}
