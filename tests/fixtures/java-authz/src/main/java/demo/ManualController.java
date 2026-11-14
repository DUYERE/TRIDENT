package demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/manual")
public class ManualController {
    @RequestMapping("/check")
    public String check(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return "redirect:/login";
        }
        return "manual/check";
    }
}
