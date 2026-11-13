package example.container;

import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.dom4j.io.SAXReader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContainerReflectController {
    private Connection connection;

    // fixture:container-mutate
    @GetMapping("/container/mutate")
    public void mutate(@RequestParam("name") String name) throws Exception {
        List<String> values = new ArrayList<>();
        fill(values, name);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:container-clear
    @GetMapping("/container/clear")
    public void clear(@RequestParam("name") String name) throws Exception {
        List<String> values = new ArrayList<>();
        values.add(name);
        values.clear();
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:container-clear-refill
    @GetMapping("/container/clear-refill")
    public void refill(@RequestParam("name") String name) throws Exception {
        List<String> values = new ArrayList<>();
        values.add(name);
        values.clear();
        values.add(name);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:container-helper-clear
    @GetMapping("/container/helper-clear")
    public void helperClear(@RequestParam("name") String name) throws Exception {
        List<String> values = new ArrayList<>();
        fillThenClear(values, name);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:container-constant
    @GetMapping("/container/constant")
    public void constant(@RequestParam("name") String name) throws Exception {
        List<String> values = new ArrayList<>();
        values.add("constant");
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:reflected-return
    @GetMapping("/reflect/return")
    public String reflect(@RequestParam("q") String q) {
        return q;
    }

    // fixture:reflected-clean
    @GetMapping("/reflect/clean")
    public String clean(@RequestParam("q") String q) {
        return "safe";
    }

    // fixture:xxe-sax-reader
    @GetMapping("/xxe/sax-reader")
    public void sax(@RequestParam("xml") String xml) throws Exception {
        SAXReader reader = new SAXReader();
        reader.read(xml);
    }

    private static void fill(List<String> values, String name) {
        // fixture:container-helper-add
        values.add(name);
    }

    private static void fillThenClear(List<String> values, String name) {
        values.add(name);
        values.clear();
    }
}
