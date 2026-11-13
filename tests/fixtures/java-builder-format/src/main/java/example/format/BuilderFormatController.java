package example.format;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [01] Intentionally vulnerable training material; SQL construction variants only.
@RestController
@RequestMapping("/synthetic/format")
public final class BuilderFormatController {
    private final Connection connection;

    public BuilderFormatController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/builder")
    public void builder(@RequestParam("q") String q) throws SQLException {
        // [02] fixture:builder-append; tainted append reaches StringBuilder.toString().
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT id FROM synthetic_customers WHERE name = '");
        sql.append(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }

    @GetMapping("/buffer")
    public void buffer(@RequestParam("q") String q) throws SQLException {
        // [03] fixture:buffer-append; StringBuffer content is copied into a String.
        StringBuffer sql = new StringBuffer();
        sql.append(q);
        String query = sql.toString();
        Statement statement = connection.createStatement();
        statement.executeQuery(query);
    }

    @GetMapping("/builder-constant")
    public void builderConstant(@RequestParam("q") String q) throws SQLException {
        // [04] fixture:builder-constant; constant-only builder is not a SQL sink.
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT id FROM synthetic_customers WHERE name = ?");
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }

    @GetMapping("/format")
    public void format(@RequestParam("q") String q) throws SQLException {
        // [05] fixture:string-format; literal pattern with %s consumes the source.
        String sql = String.format("SELECT id FROM synthetic_customers WHERE name = '%s'", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/format-sink")
    public void formatSink(@RequestParam("q") String q) throws SQLException {
        Statement statement = connection.createStatement();
        statement.executeQuery(String.format("SELECT id FROM synthetic_customers WHERE name = '%s'", q));
    }

    @GetMapping("/format-constant")
    public void formatConstant(@RequestParam("q") String q) throws SQLException {
        // [06] fixture:format-ignored-argument; no conversion, so q is not consumed.
        String sql = String.format("SELECT id FROM synthetic_customers WHERE name = '100%%' AND id = ?", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/format-dynamic")
    public void formatDynamic(@RequestParam("q") String q, @RequestParam("fmt") String fmt) throws SQLException {
        // [07] fixture:format-dynamic; computed pattern is an inconclusive boundary.
        String sql = String.format(fmt, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/builder-boundary")
    public void builderBoundary(@RequestParam("q") String q) throws SQLException {
        // [08] fixture:builder-boundary; an unresolved helper may mutate the builder.
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT id FROM synthetic_customers WHERE name = '");
        externalBuilder(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
}
