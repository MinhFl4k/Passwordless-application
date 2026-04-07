document.addEventListener("DOMContentLoaded", function () {

    const sendBtn = document.getElementById("sendOtpBtn");
    const otpForm = document.querySelector("form[action*='otp-login-process']");
    const sendForm = document.querySelector("form[action*='send-otp']");
    const otpInput = document.querySelector("input[name='otp']");

    const COOLDOWN_TIME = 60;
    const STORAGE_KEY = "otpCooldownStart";

    function startCooldown(seconds) {
        if (!sendBtn) return;

        let timeLeft = seconds;
        sendBtn.disabled = true;

        const interval = setInterval(() => {
            sendBtn.innerText = "Please wait " + timeLeft + "s";
            timeLeft--;

            if (timeLeft < 0) {
                clearInterval(interval);
                sendBtn.disabled = false;
                sendBtn.innerText = "Send OTP";
                localStorage.removeItem(STORAGE_KEY);
            }
        }, 1000);
    }

    function restoreCooldown() {
        const startTime = localStorage.getItem(STORAGE_KEY);
        if (!startTime) return;

        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const remaining = COOLDOWN_TIME - elapsed;

        if (remaining > 0) {
            startCooldown(remaining);
        } else {
            localStorage.removeItem(STORAGE_KEY);
        }
    }

    if (sendBtn && sendForm) {
        sendForm.addEventListener("submit", function () {
            localStorage.setItem(STORAGE_KEY, Date.now());

            sendBtn.disabled = true;
            sendBtn.innerText = "Sending...";
        });
    }


    if (otpForm) {
        otpForm.addEventListener("submit", function (e) {
            if (otpForm.classList.contains("submitted")) {
                e.preventDefault();
                return;
            }
            otpForm.classList.add("submitted");
        });
    }

    if (otpInput) {
        otpInput.addEventListener("input", function () {
            this.value = this.value.replace(/\D/g, "");

            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
            }
        });
    }

    restoreCooldown();
});