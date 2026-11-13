package example.dispatch;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [05] Intentionally vulnerable training material; dispatch and field flows.
@RestController
@RequestMapping("/synthetic/dispatch")
public final class DispatchFieldController {
    private final Connection connection;
    private final Lookup lookup;
    private final Ambiguous ambiguous;
    private final ChildRepo child;
    private final OverrideRepo override;
    private String stored;

    public DispatchFieldController(Connection connection, Lookup lookup, Ambiguous ambiguous,
                                   ChildRepo child, OverrideRepo override) {
        this.connection = connection;
        this.lookup = lookup;
        this.ambiguous = ambiguous;
        this.child = child;
        this.override = override;
    }

    @GetMapping("/iface")
    public void iface(@RequestParam("q") String q) throws SQLException {
        String sql = lookup.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/iface-ambiguous")
    public void ifaceAmbiguous(@RequestParam("q") String q) throws SQLException {
        String sql = ambiguous.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/extends")
    public void extendsFlow(@RequestParam("q") String q) throws SQLException {
        String sql = child.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/override")
    public void overrideFlow(@RequestParam("q") String q) throws SQLException {
        String sql = override.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/field")
    public void field(@RequestParam("q") String q) throws SQLException {
        store(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(this.stored);
    }

    @GetMapping("/field-copy")
    public void fieldCopy(@RequestParam("q") String q) throws SQLException {
        store(q);
        String sql = this.stored;
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/field-constant")
    public void fieldConstant(@RequestParam("q") String q) throws SQLException {
        storeConstant(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(this.stored);
    }

    @GetMapping("/field-inherited")
    public void fieldInherited(@RequestParam("q") String q) throws SQLException {
        child.save(q);
        String sql = child.readInherited();
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    private void store(String value) {
        // [06] fixture:field-write
        this.stored = value;
    }

    private void storeConstant(String value) {
        this.stored = "SELECT id FROM synthetic_customers WHERE id = ?";
    }
}
