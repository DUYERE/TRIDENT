package example.inject;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [07] Intentionally vulnerable training material; non-SQL injection sinks.
@RestController
@RequestMapping("/synthetic/inject")
public final class InjectionController {
    private final CommandService commandService = new CommandService();
    private final SsrfService ssrfService = new SsrfService();
    private final PathService pathService = new PathService();
    private final TemplateService templateService = new TemplateService();

    @GetMapping("/command")
    public String command(@RequestParam("q") String q) throws Exception {
        return commandService.run(q);
    }

    @GetMapping("/command-builder")
    public void commandBuilder(@RequestParam("q") String q) throws Exception {
        commandService.runBuilder(q);
    }

    @GetMapping("/command-constant")
    public void commandConstant(@RequestParam("q") String q) throws Exception {
        commandService.runConstant(q);
    }

    @GetMapping("/command-dynamic")
    public void commandDynamic(@RequestParam("q") String q) throws Exception {
        commandService.runDynamic(q);
    }

    @GetMapping("/ssrf")
    public void ssrf(@RequestParam("q") String q) throws Exception {
        ssrfService.fetch(q);
    }

    @GetMapping("/ssrf-rest")
    public void ssrfRest(@RequestParam("q") String q) {
        ssrfService.fetchRest(q);
    }

    @GetMapping("/ssrf-constant")
    public void ssrfConstant(@RequestParam("q") String q) throws Exception {
        ssrfService.fetchConstant(q);
    }

    @GetMapping("/path")
    public void path(@RequestParam("q") String q) throws Exception {
        pathService.read(q);
    }

    @GetMapping("/path-files")
    public void pathFiles(@RequestParam("q") String q) throws Exception {
        pathService.readFiles(q);
    }

    @GetMapping("/path-constant")
    public void pathConstant(@RequestParam("q") String q) throws Exception {
        pathService.readConstant(q);
    }

    @GetMapping("/template")
    public void template(@RequestParam("q") String q) {
        templateService.evaluate(q);
    }

    @GetMapping("/template-engine")
    public void templateEngine(@RequestParam("q") String q) {
        templateService.render(q);
    }
}
