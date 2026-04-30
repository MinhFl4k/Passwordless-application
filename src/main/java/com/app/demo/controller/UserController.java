package com.app.demo.controller;

import com.app.demo.dto.request.ChangePasswordDto;
import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.dto.response.PasskeyResponseDto;
import com.app.demo.dto.response.UserResponseDto;
import com.app.demo.service.PasskeyManageService;
import com.app.demo.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final PasskeyManageService passkeyManageService;

    @GetMapping("/home")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER', 'GUEST')")
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
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String showEditPage(Authentication authentication, Model model) {
        UserResponseDto userResponseDto = userService.getUserInfo(authentication);
        model.addAttribute("user", userResponseDto);
        return "edit";
    }

    @PostMapping("/edit-profile")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String updateProfile(
            @Valid @ModelAttribute("user") UserUpdateDto userDto,
            BindingResult result,
            Authentication authentication,
            RedirectAttributes redirectAttributes
    ) {
        if (result.hasErrors()) {
            return "edit";
        }
        try {
            boolean emailChanged = userService.updateUserInfo(authentication, userDto);
            if (emailChanged) {
                redirectAttributes.addFlashAttribute("successMessage", "Please check your email inbox");
            }
        } catch (RuntimeException e) {
            throw new RuntimeException(e.getMessage());
        }

        return "redirect:/home";
    }

    @GetMapping("/change-password")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String showChangePasswordPage(Model model) {
        model.addAttribute("passwordDto", new ChangePasswordDto());
        return "change-password";
    }

    @PostMapping("/change-password")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String changePassword(
            @Valid @ModelAttribute("passwordDto") ChangePasswordDto changePasswordDTO,
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
            throw new RuntimeException(e.getMessage());
        }

        return "redirect:/home";
    }

    @GetMapping("/account-passkey")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String showAccountPasskeyPage(Authentication authentication, Model model) {
        String username = authentication.getName();
        List<PasskeyResponseDto> passkeys = this.passkeyManageService.findPasskeysByUsername(username);
        model.addAttribute("passkeys", passkeys);
        return "account-passkey";
    }

    @PostMapping("/passkeys/delete")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public String deletePasskey(
            @RequestParam("credentialId") String credentialId,
            Authentication authentication) {
        String username = authentication.getName();
        this.passkeyManageService.deletePasskeyForUser(username, credentialId);
        return "redirect:/account-passkey";
    }
}
