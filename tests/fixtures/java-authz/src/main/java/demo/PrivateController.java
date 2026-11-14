package demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/private")
public class PrivateController {
    @RequestMapping("/data")
    public String data() {
        return "api/private/data";
    }
}
