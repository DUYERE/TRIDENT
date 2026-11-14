package demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/xmlfilter")
public class XmlFilteredController {
    @RequestMapping("/data")
    public String data() {
        return "xmlfilter/data";
    }
}
