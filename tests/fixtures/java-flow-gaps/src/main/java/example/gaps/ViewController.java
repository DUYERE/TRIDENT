package example.gaps;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

// A plain Controller returns a view name, not a response body, so a tainted
// String return must not be reported as reflected XSS.
@Controller
public class ViewController {
    @GetMapping("/reflect/view")
    public String view(@RequestParam("q") String q) {
        return q;
    }
}
