package chain;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/chain/api")
public class ApiController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/public/info")
    public String info() {
        return "info";
    }

    @GetMapping("/admin/panel")
    public String panel() {
        return "panel";
    }
}
