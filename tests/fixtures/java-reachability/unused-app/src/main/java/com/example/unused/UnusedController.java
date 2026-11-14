package com.example.unused;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// [03] Entrypoint that never references the declared dependency.
@RestController
public class UnusedController {

    @GetMapping("/unused")
    public String handle() {
        return "ok";
    }
}
