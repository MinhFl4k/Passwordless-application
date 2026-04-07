package com.app.demo.controller;

import com.app.demo.dto.request.UserSignupDto;
import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.dto.request.ChangePasswordDTO;
import com.app.demo.dto.response.UserResponseDto;
import com.app.demo.service.EmailService;
import com.app.demo.service.OtpService;
import com.app.demo.service.UserService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
public class HomeController {

    private final UserService userService;
    private final EmailService emailService;
    private final OtpService otpService;

    public HomeController(UserService userService, EmailService emailService, OtpService otpService) {
        this.userService = userService;
        this.emailService = emailService;
        this.otpService = otpService;
    }

    @GetMapping("/login")
    public String showLoginPage(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }
        return "login";
    }

    @GetMapping("/otp-login")
    public String showOtpLoginPage(HttpSession session, Model model, Authentication authentication) {

        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }
        Object error = session.getAttribute("FLASH_ERROR");

        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }
        model.addAttribute("email", session.getAttribute("email"));

        return "otp-login";
    }

    @PostMapping("/send-otp")
    public String sendOtp(@RequestParam("username") String email,
                          HttpSession session) {
        try {
            String otp = otpService.generateOtp(email);
            emailService.sendOtp(email, otp);
            session.setAttribute("email", email);

        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/otp-login?sent=true";
    }

    @GetMapping("/signup")
    public String showSignupPage(Model model, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }
        model.addAttribute("user", new UserSignupDto());
        return "signup";
    }

    @PostMapping("/signup")
    public String signupUser(
            @Valid @ModelAttribute("user") UserSignupDto userSignupDto,
            BindingResult result
    ) {
        if (result.hasErrors()) {
            return "signup";
        }
        userService.signupUser(userSignupDto);
        return "redirect:/login?signupSuccess";
    }

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
