package demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/open")
public class OpenController {
    @RequestMapping("/hello")
    public String hello() {
        return "open/hello";
    }
}
