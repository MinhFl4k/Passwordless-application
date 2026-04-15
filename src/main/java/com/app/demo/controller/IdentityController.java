package com.app.demo.controller;

import com.app.demo.dto.request.EmailRequestDTO;
import com.app.demo.dto.request.UserSignupDto;
import com.app.demo.service.EmailService;
import com.app.demo.service.LoginWithLinkService;
import com.app.demo.service.LoginWithOtpService;
import com.app.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class IdentityController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private LoginWithOtpService loginWithOtpService;

    @Autowired
    private LoginWithLinkService loginWithLinkService;

    @Value("${account.locked.error.message}")
    private String ACCOUNT_LOCKED_ERROR_MESSAGE;

    @GetMapping("/new-login")
    public String showNewLoginPage(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

        model.addAttribute("emailRequest", new EmailRequestDTO());
        return "new-login";
    }

    @PostMapping("/new-login")
    public String handleNewLogin(
            @Valid @ModelAttribute("emailRequest") EmailRequestDTO emailRequestDTO,
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

        String test = "otp";
//        String test = "magic";

        String yess = "otp";

        try {
            if (yess.equalsIgnoreCase(test)) {
                String otp = loginWithOtpService.generateOtp(email);
                emailService.sendOtp(email, otp);

                session.setAttribute("email", email);

                return "redirect:/new-login-with-otp";
            } else {
                loginWithLinkService.sendLink(email);

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

        model.addAttribute("email", session.getAttribute("email"));
        session.setAttribute("OTP_LOGIN_FLOW", "NEW_FLOW");
        return "new-login-with-otp";
    }

    @GetMapping("/new-login-with-link")
    public String showNewLoginWithLinkPage(
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

    @GetMapping("/login-with-link")
    public String showLoginWithLinkPage(
            Authentication authentication,
            Model model
    ) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }
        model.addAttribute("emailRequest", new EmailRequestDTO());
        return "login-with-link";
    }

    @PostMapping("/auth/send-link-login")
    public String sendLink(
            @Valid @ModelAttribute("emailRequest") EmailRequestDTO emailRequestDTO,
            BindingResult bindingResult,
            RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "login-with-link";
        }

        String email = emailRequestDTO.getEmail();

        try {
            loginWithLinkService.sendLink(email);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Please check your email inbox");
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/login-with-link";
    }

    @GetMapping("/auth/link-login-process")
    public String loginWithLink(
            @RequestParam String token,
            HttpServletRequest request,
            HttpSession session
    ) {
        try {
            loginWithLinkService.loginWithLink(token, request);
            return "redirect:/home";
        } catch (org.springframework.security.authentication.LockedException e) {
            session.setAttribute("FLASH_ERROR",
                    ACCOUNT_LOCKED_ERROR_MESSAGE);
            return "redirect:/account-locked";
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return "error";
        }
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
        model.addAttribute("emailRequest", new EmailRequestDTO());
        model.addAttribute("email", session.getAttribute("email"));
        session.setAttribute("OTP_LOGIN_FLOW", "OLD_FLOW");

        return "login-with-otp";
    }

    @PostMapping("/send-otp")
    public String sendOtp(
            @Valid @ModelAttribute("emailRequest") EmailRequestDTO emailRequestDTO,
            BindingResult bindingResult,
            HttpSession session
    ) {
        if (bindingResult.hasErrors()) {
            return "login-with-otp";
        }
        String email = emailRequestDTO.getEmail();
        try {
            String otp = loginWithOtpService.generateOtp(email);
            emailService.sendOtp(email, otp);
            session.setAttribute("email", email);

        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
        return "redirect:/login-with-otp?sent=true";
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
}
