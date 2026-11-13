package example.extra;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [08] Intentionally vulnerable training material; XSS, deserialization, XXE
// and LDAP injection sinks.
@RestController
@RequestMapping("/synthetic/extra")
public final class ExtraSinkController {
    private final InitialDirContext dirContext = new InitialDirContext();
    private final LdapTemplate ldapTemplate = new LdapTemplate();

    @GetMapping("/xss-chain")
    public void xssChain(@RequestParam("q") String q, HttpServletResponse response) throws Exception {
        // fixture:xss-chain
        response.getWriter().write(q);
    }

    @GetMapping("/xss-writer")
    public void xssWriter(@RequestParam("q") String q, PrintWriter writer) {
        // fixture:xss-writer
        writer.print(q);
    }

    @GetMapping("/xss-constant")
    public void xssConstant(@RequestParam("q") String q, PrintWriter writer) {
        writer.println("trident-fixed");
    }

    @GetMapping("/xss-dynamic")
    public void xssDynamic(@RequestParam("q") String q, PrintWriter writer) {
        // fixture:xss-dynamic
        writer.write(String.format(q));
    }

    @GetMapping("/deserialization")
    public void deserialization(@RequestParam("q") String q) throws Exception {
        // fixture:deserialization
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(q.getBytes()));
        stream.readObject();
    }

    @GetMapping("/deserialization-constant")
    public void deserializationConstant(@RequestParam("q") String q) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream("trident-fixed".getBytes()));
        stream.readObject();
    }

    @GetMapping("/xml-decoder")
    public void xmlDecoder(@RequestParam("q") String q) {
        // fixture:xml-decoder
        XMLDecoder decoder = new XMLDecoder(q);
        decoder.readObject();
    }

    @GetMapping("/xxe-dom")
    public void xxeDom(@RequestParam("q") String q) throws Exception {
        // fixture:xxe-dom
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        builder.parse(q);
    }

    @GetMapping("/xxe-sax")
    public void xxeSax(@RequestParam("q") String q, SAXParser parser) throws Exception {
        // fixture:xxe-sax
        parser.parse(q, null);
    }

    @GetMapping("/xxe-constant")
    public void xxeConstant(@RequestParam("q") String q) throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        builder.parse("/tmp/trident-fixed.xml");
    }

    @GetMapping("/xxe-dynamic")
    public void xxeDynamic(@RequestParam("q") String q) throws Exception {
        // fixture:xxe-dynamic
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        builder.parse(String.format(q));
    }

    @GetMapping("/ldap-search")
    public void ldapSearch(@RequestParam("q") String q) throws Exception {
        // fixture:ldap-search
        dirContext.search("dc=example,dc=com", q, new SearchControls());
    }

    @GetMapping("/ldap-lookup")
    public void ldapLookup(@RequestParam("q") String q) {
        // fixture:ldap-lookup
        ldapTemplate.lookup(q);
    }

    @GetMapping("/ldap-constant")
    public void ldapConstant(@RequestParam("q") String q) throws Exception {
        ldapTemplate.search("dc=example,dc=com", "(objectClass=person)", new SearchControls());
    }
}
