package demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/xmlsecure")
public class XmlSecureController {
    @RequestMapping("/data")
    public String data() {
        return "xmlsecure/data";
    }
}
