package example.gaps;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.xml.stream.XMLInputFactory;

import org.apache.commons.digester3.Digester;
import org.dom4j.DocumentHelper;
import org.jdom2.input.SAXBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [16] Intentionally vulnerable training material; array subscripts, remove,
// field collections, produces-aware reflected returns, chained deserialization
// and additional XXE entry points.
@RestController
public class GapController {
    private Connection connection;
    private List<String> items = new ArrayList<>();

    // fixture:array-write
    @GetMapping("/array/write")
    public void arrayWrite(@RequestParam("q") String q) throws Exception {
        String[] parts = new String[1];
        parts[0] = q;
        String name = parts[0];
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + name + "'");
    }

    @GetMapping("/array/constant")
    public void arrayConstant(@RequestParam("q") String q) throws Exception {
        String[] parts = new String[1];
        parts[0] = "fixed";
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + parts[0] + "'");
    }

    // fixture:array-helper
    @GetMapping("/array/helper")
    public void arrayHelper(@RequestParam("q") String q) throws Exception {
        String[] parts = new String[1];
        fillArray(parts, q);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + parts[0] + "'");
    }

    // fixture:collection-remove
    @GetMapping("/remove/keep")
    public void removeKeep(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<>();
        values.add(q);
        values.remove(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:field-collection
    @GetMapping("/field/keep")
    public void fieldKeep(@RequestParam("q") String q) throws Exception {
        items.add(q);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + items.get(0) + "'");
    }

    // fixture:field-clear
    @GetMapping("/field/clear")
    public void fieldClear(@RequestParam("q") String q) throws Exception {
        items.add(q);
        items.clear();
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + items.get(0) + "'");
    }

    @GetMapping(value = "/reflect/html", produces = "text/html")
    public String reflectHtml(@RequestParam("q") String q) {
        return q;
    }

    @GetMapping(value = "/reflect/json", produces = "application/json")
    public String reflectJson(@RequestParam("q") String q) {
        return q;
    }

    @GetMapping(value = "/reflect/constant-html", produces = "text/html")
    public String reflectConstantHtml(@RequestParam("q") String q) {
        return "safe";
    }

    // fixture:deserialize-chain
    @GetMapping("/deserialize/chain")
    public void deserializeChain(@RequestParam("q") String q) throws Exception {
        new ObjectInputStream(new ByteArrayInputStream(q.getBytes())).readObject();
    }

    @GetMapping("/deserialize/chain-constant")
    public void deserializeChainConstant(@RequestParam("q") String q) throws Exception {
        new ObjectInputStream(new ByteArrayInputStream("fixed".getBytes())).readObject();
    }

    // fixture:xxe-build
    @GetMapping("/xxe/build")
    public void xxeBuild(@RequestParam("xml") String xml) throws Exception {
        SAXBuilder builder = new SAXBuilder();
        builder.build(xml);
    }

    // fixture:xxe-digester
    @GetMapping("/xxe/digester")
    public void xxeDigester(@RequestParam("xml") String xml) throws Exception {
        Digester digester = new Digester();
        digester.parse(xml);
    }

    // fixture:xxe-helper
    @GetMapping("/xxe/helper")
    public void xxeHelper(@RequestParam("xml") String xml) throws Exception {
        DocumentHelper.parseText(xml);
    }

    // fixture:xxe-event
    @GetMapping("/xxe/event")
    public void xxeEvent(@RequestParam("xml") String xml) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.createXMLEventReader(new StringReader(xml));
    }

    private static void fillArray(String[] values, String name) {
        // fixture:array-helper-write
        values[0] = name;
    }
}
