package demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/secure")
public class SecureController {
    @RequestMapping("/admin")
    public String admin() {
        return "secure/admin";
    }

    @RequestMapping("/login")
    public String login() {
        return "secure/login";
    }
}
