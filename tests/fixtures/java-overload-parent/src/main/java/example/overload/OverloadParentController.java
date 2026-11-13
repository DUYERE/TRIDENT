package example.overload;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [04] Intentionally vulnerable training material; overload and parent resolution.
@RestController
@RequestMapping("/synthetic/overload")
public final class OverloadParentController {
    private final Connection connection;
    private final TypedLookup typed;
    private final TypedRepo repo;
    private final ExternalBase external;
    private final LocalParent local;

    public OverloadParentController(Connection connection, TypedLookup typed, TypedRepo repo,
                                    ExternalBase external, LocalParent local) {
        this.connection = connection;
        this.typed = typed;
        this.repo = repo;
        this.external = external;
        this.local = local;
    }

    @GetMapping("/string")
    public void string(@RequestParam("q") String q) throws SQLException {
        String sql = typed.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/int")
    public void integer(@RequestParam("id") int id) throws SQLException {
        String sql = repo.find(id);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/object")
    public void object(@RequestParam("value") Object value) throws SQLException {
        // [05] fixture:ambiguous-overload; Object fits neither String nor Integer.
        String sql = repo.find(value);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/parent")
    public void parent(@RequestParam("q") String q) throws SQLException {
        // [06] fixture:unresolved-parent-call; build may live on MissingBase.
        String sql = external.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }

    @GetMapping("/local-parent")
    public void localParent(@RequestParam("q") String q) throws SQLException {
        String sql = local.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
