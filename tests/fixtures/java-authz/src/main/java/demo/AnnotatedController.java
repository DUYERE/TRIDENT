package demo;

import javax.annotation.security.PermitAll;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api")
public class AnnotatedController {
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping("/admin")
    public String admin() {
        return "api/admin";
    }

    @PermitAll
    @RequestMapping("/open")
    public String open() {
        return "api/open";
    }
}
