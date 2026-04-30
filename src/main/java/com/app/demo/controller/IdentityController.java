package com.app.demo.controller;

import com.app.demo.dto.request.EmailRequestDto;
import com.app.demo.dto.request.UserSignupDto;
import com.app.demo.enums.ErrorMessage;
import com.app.demo.enums.UserTokenType;
import com.app.demo.service.EmailService;
import com.app.demo.service.TokenLoginService;
import com.app.demo.service.OtpLoginService;
import com.app.demo.service.UserService;
import com.app.demo.validation.sequence.ValidationSequence;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class IdentityController {

    private final UserService userService;

    private final EmailService emailService;

    private final OtpLoginService otpLoginService;

    private final TokenLoginService tokenLoginService;

    @GetMapping("/new-login")
    public String showNewLoginPage(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        model.addAttribute("emailRequest", new EmailRequestDto());
        return "new-login";
    }

    @PostMapping("/new-login")
    public String handleNewLogin(
            @Validated(ValidationSequence.class) @ModelAttribute("emailRequest") EmailRequestDto emailRequestDTO,
            BindingResult bindingResult,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            Authentication authentication,
            Model model
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        if (bindingResult.hasErrors()) {
            return "new-login";
        }

        String email = emailRequestDTO.getEmail();

        String type = "otp";

        try {
            if (type.equalsIgnoreCase("otp")) {

                String otp = otpLoginService.generateOtp(email);
                emailService.sendOtp(email, otp);
                session.setAttribute("OTP_LOGIN_EMAIL", email);

                return "redirect:/new-login-with-otp";
            } else if (type.equalsIgnoreCase("totp")) {

                session.setAttribute("TOTP_LOGIN_EMAIL", email);
                return "redirect:/new-login-with-totp";
            } else {
                tokenLoginService.sendUserTokenLink(email, UserTokenType.LOGIN);

                session.setAttribute("email", email);
                redirectAttributes.addFlashAttribute("email", email);

                return "redirect:/new-login-with-link";
            }
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
            return "new-login";
        }
    }

    @GetMapping("/new-login-with-otp")
    public String showNewOtpLoginPage(
            HttpSession session,
            Model model,
            Authentication authentication
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        Object error = session.getAttribute("FLASH_ERROR");
        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }

        model.addAttribute("email", session.getAttribute("OTP_LOGIN_EMAIL"));
        session.setAttribute("OTP_LOGIN_FLOW", "NEW_FLOW");
        return "new-login-with-otp";
    }

    @GetMapping("/new-login-with-totp")
    public String showNewTotpLoginPage(
            HttpSession session,
            Model model,
            Authentication authentication
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        Object error = session.getAttribute("FLASH_ERROR");
        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }

        model.addAttribute("email", session.getAttribute("TOTP_LOGIN_EMAIL"));
        session.setAttribute("TOTP_LOGIN_FLOW", "NEW_FLOW");
        return "new-login-with-totp";
    }

    @GetMapping("/new-login-with-link")
    public String showNewMagicLinkLoginPage(
            HttpSession session,
            Model model,
            Authentication authentication
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        model.addAttribute("email", session.getAttribute("email"));
        return "new-login-with-link";
    }


    @GetMapping("/login")
    public String showLoginPage(Authentication authentication,
                            HttpSession session,
                            Model model
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        Object error = session.getAttribute("FLASH_ERROR");
        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }

        return "login";
    }

    @GetMapping("/login-with-otp")
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
        model.addAttribute("emailRequest", new EmailRequestDto());
        model.addAttribute("email", session.getAttribute("OTP_LOGIN_EMAIL"));
        session.setAttribute("OTP_LOGIN_FLOW", "OLD_FLOW");

        return "login-with-otp";
    }

    @GetMapping("/login-with-totp")
    public String showTotpLoginPage(
            HttpSession session,
            Authentication authentication,
            Model model
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        Object error = session.getAttribute("FLASH_ERROR");

        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }
        session.setAttribute("TOTP_LOGIN_FLOW", "OLD_FLOW");

        return "login-with-totp";
    }

    @GetMapping("/login-with-link")
    public String showMagicLinkLoginPage(
            Authentication authentication,
            Model model
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }
        model.addAttribute("emailRequest", new EmailRequestDto());
        return "login-with-link";
    }

    @PostMapping("/send-otp")
    public String sendOtp(
            @Validated(ValidationSequence.class) @ModelAttribute("emailRequest") EmailRequestDto emailRequestDTO,
            BindingResult bindingResult,
            HttpSession session
    ) {
        if (bindingResult.hasErrors()) {
            return "login-with-otp";
        }
        String email = emailRequestDTO.getEmail();
        try {
            String otp = otpLoginService.generateOtp(email);
            emailService.sendOtp(email, otp);
            session.setAttribute("OTP_LOGIN_EMAIL", email);

        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/login-with-otp?sent=true";
    }

    @PostMapping("/auth/send-link-login")
    public String sendLoginLink(
            @Validated(ValidationSequence.class) @ModelAttribute("emailRequest") EmailRequestDto emailRequestDTO,
            BindingResult bindingResult,
            RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "login-with-link";
        }

        String email = emailRequestDTO.getEmail();

        try {
            tokenLoginService.sendUserTokenLink(email, UserTokenType.LOGIN);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Please check your email inbox");
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/login-with-link";
    }

    @PostMapping("/auth/send-link-verify")
    public String sendVerifyLink(
            Authentication authentication,
            RedirectAttributes redirectAttributes
    ) {
        if (authentication == null || authentication.getName() == null || authentication.getName().isBlank()) {
            return "redirect:/login";
        }
        String email = authentication.getName();

        try {
            tokenLoginService.sendUserTokenLink(email, UserTokenType.VERIFY);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Please check your email inbox");
        } catch (RuntimeException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/home";
    }

    @GetMapping("/auth/login")
    public String userTokenLoginProcess(
            @RequestParam String token,
            HttpServletRequest request,
            HttpSession session
    ) {
        try {
            tokenLoginService.loginWithUserToken(token, request);
            return "redirect:/home";
        } catch (org.springframework.security.authentication.LockedException e) {
            session.setAttribute("FLASH_ERROR", ErrorMessage.ACCOUNT_LOCKED.getMessage());
            return "redirect:/account-locked";
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return "error";
        }
    }

    @GetMapping("/auth/verify")
    public String userTokenVerifyProcess(
            @RequestParam String token,
            HttpServletRequest request,
            HttpSession session
    ) {
        try {
            tokenLoginService.verifyWithUserToken(token, request);
            return "redirect:/account-verified";
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return "error";
        }
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

    @GetMapping("/account-locked")
    public String showAccountLockedPage(HttpSession session, Model model) {
        Object error = session.getAttribute("FLASH_ERROR");
        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("FLASH_ERROR");
        }
        return "account-locked";
    }

    @GetMapping("/account-verified")
    public String showAccountVerifiedPage() {
        return "account-verified";
    }

    @GetMapping("/access-denied")
    public String showAccessDeniedPage() {
        return "access-denied";
    }
}
