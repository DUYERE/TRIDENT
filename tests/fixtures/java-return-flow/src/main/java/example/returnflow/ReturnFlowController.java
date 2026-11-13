package example.returnflow;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [01] Intentionally vulnerable training material; tainted return and builder mutation.
@RestController
@RequestMapping("/synthetic/return")
public final class ReturnFlowController {
    private final Connection connection;

    public ReturnFlowController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/sink")
    public void sink(@RequestParam("q") String q) throws SQLException {
        String sql = buildQuery(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/sink-direct")
    public void sinkDirect(@RequestParam("q") String q) throws SQLException {
        Statement statement = connection.createStatement();
        statement.executeQuery(buildQuery(q));
    }

    @GetMapping("/constant")
    public void constant(@RequestParam("q") String q) throws SQLException {
        // [02] fixture:return-constant; a clean return is not tainted by its argument.
        String sql = constantQuery(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/dynamic")
    public void dynamic(@RequestParam("q") String q, @RequestParam("fmt") String fmt) throws SQLException {
        String sql = dynamicQuery(fmt, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/builder")
    public void builder(@RequestParam("q") String q) throws SQLException {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT id FROM synthetic_customers WHERE name = '");
        appendValue(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }

    @GetMapping("/builder-constant")
    public void builderConstant(@RequestParam("q") String q) throws SQLException {
        // [03] fixture:builder-mutation-constant; the helper ignores its value.
        StringBuilder sql = new StringBuilder();
        appendConstant(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }

    private String buildQuery(String value) {
        // [04] fixture:return-concat
        return "SELECT id FROM synthetic_customers WHERE name = '" + value + "'";
    }

    private String constantQuery(String value) {
        return "SELECT id FROM synthetic_customers WHERE name = ?";
    }

    private String dynamicQuery(String pattern, String value) {
        return String.format(pattern, value);
    }

    private void appendValue(StringBuilder builder, String value) {
        // [05] fixture:builder-mutation
        builder.append(value);
    }

    private void appendConstant(StringBuilder builder, String value) {
        builder.append("SELECT id FROM synthetic_customers WHERE id = ?");
    }
}
