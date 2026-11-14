package com.example.reflect;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// [04] Entrypoint that loads the dependency class by name; the bounded graph
// cannot follow this edge, so reachability must stay unknown.
@RestController
public class ReflectController {

    @GetMapping("/reflect")
    public String handle() throws Exception {
        return Class.forName("org.example.lib.LibApi").getName();
    }
}
