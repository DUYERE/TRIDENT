package example.advanced;

import example.helperb.Helper;
import java.io.File;
import java.net.URI;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;
import java.net.http.HttpRequest;

// [17] Intentionally vulnerable training material: framework SQL/SSRF sinks,
// upload writes, element-level container precision and import-aware resolution.
@RestController
public class AdvancedController {
    private final JdbcTemplate jdbcTemplate = new JdbcTemplate();
    private final EntityManager entityManager = null;
    private final WebClient webClient = WebClient.create();
    private final Connection connection = null;

    // fixture:sql-template
    @GetMapping("/sql/template")
    public void template(@RequestParam("q") String q) {
        jdbcTemplate.update("SELECT * FROM t WHERE n='" + q + "'");
    }

    @GetMapping("/sql/template-safe")
    public void templateSafe(@RequestParam("q") String q) {
        jdbcTemplate.update("SELECT * FROM t WHERE n=?", q);
    }

    // fixture:sql-jpa
    @GetMapping("/sql/jpa")
    public void jpa(@RequestParam("q") String q) {
        entityManager.createQuery("SELECT u FROM User u WHERE u.name='" + q + "'");
    }

    // fixture:ssrf-httpclient
    @GetMapping("/ssrf/httpclient")
    public void httpClient(@RequestParam("q") String q) throws Exception {
        HttpRequest.newBuilder().uri(new URI(q)).build();
    }

    // fixture:ssrf-webclient
    @GetMapping("/ssrf/webclient")
    public void webClient(@RequestParam("q") String q) {
        webClient.get().uri(q);
    }

    // fixture:upload-transfer
    @GetMapping("/upload/transfer")
    public void upload(@RequestParam("q") String q, MultipartFile upload) throws Exception {
        upload.transferTo(new File("/tmp/" + q));
    }

    @GetMapping("/upload/constant")
    public void uploadConstant(MultipartFile upload) throws Exception {
        upload.transferTo(new File("/tmp/fixed"));
    }

    // fixture:array-element-clean
    @GetMapping("/array/precise")
    public void precise(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<>();
        values.set(0, q);
        values.set(1, "safe");
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(1) + "'");
    }

    // fixture:array-element-tainted
    @GetMapping("/array/precise-tainted")
    public void preciseTainted(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<>();
        values.set(0, q);
        values.set(1, "safe");
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:array-remove-index
    @GetMapping("/array/remove-index")
    public void removeIndex(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<>();
        values.set(0, q);
        values.remove(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE n='" + values.get(0) + "'");
    }

    // fixture:import-helper
    @GetMapping("/import/helper")
    public void importedHelper(@RequestParam("q") String q) throws Exception {
        Helper helper = new Helper();
        String sql = helper.run(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/import/clean")
    public void importedClean(@RequestParam("q") String q) throws Exception {
        Helper helper = new Helper();
        String sql = helper.run("fixed");
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
