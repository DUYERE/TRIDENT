package chain;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/chain/web")
public class WebController {

    @GetMapping("/open")
    public String open() {
        return "open";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/members")
    public String members() {
        return "members";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/feature")
    public String feature() {
        return "feature";
    }

    @PreAuthorize("false")
    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @PreAuthorize("hasRole('ADMIN') or hasIpAddress('10.0.0.0/8')")
    @GetMapping("/unknown")
    public String unknown() {
        return "unknown";
    }
}
