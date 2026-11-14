package com.example.reach;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// [01] HTTP entrypoint for the reachable case.
@RestController
public class ReachController {

    private final ReachService service = new ReachService();

    @GetMapping("/reach")
    public String handle() {
        return service.render();
    }
}
