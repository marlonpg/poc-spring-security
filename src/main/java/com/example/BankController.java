package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class BankController {

    private double balance = 1000.0;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        model.addAttribute("balance", balance);
        return "dashboard";
    }

    @PostMapping("/transfer")
    public String transfer(@RequestParam String toAccount, 
                          @RequestParam double amount, 
                          Model model) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            model.addAttribute("message", 
                String.format("Transferred $%.2f to %s", amount, toAccount));
        } else {
            model.addAttribute("error", "Invalid transfer amount");
        }
        model.addAttribute("balance", balance);
        return "dashboard";
    }

    @GetMapping("/vulnerable")
    public String vulnerable(Model model) {
        model.addAttribute("balance", balance);
        return "vulnerable";
    }

    // Unsafe endpoint without CSRF protection (for demonstration)
    @PostMapping("/api/unsafe/transfer")
    @ResponseBody
    public String unsafeTransfer(@RequestParam String toAccount, 
                                @RequestParam double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            return String.format("Unsafe transfer: $%.2f to %s", amount, toAccount);
        }
        return "Transfer failed";
    }
}