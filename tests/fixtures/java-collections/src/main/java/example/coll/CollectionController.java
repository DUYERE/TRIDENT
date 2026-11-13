package example.coll;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [10] Intentionally vulnerable training material; container taint propagation
// through List/Map mutation and read.
@RestController
@RequestMapping("/synthetic/collection")
public final class CollectionController {
    private final Connection connection = DriverManager.getConnection("jdbc:trident:collection");

    @GetMapping("/sql-list")
    public void sqlList(@RequestParam("q") String q) throws Exception {
        // fixture:collection-sql-list
        List<String> values = new ArrayList<String>();
        values.add(q);
        String name = values.get(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("select * from t where name='" + name + "'");
    }

    @GetMapping("/sql-map")
    public void sqlMap(@RequestParam("q") String q) throws Exception {
        // fixture:collection-sql-map
        Map<String, String> values = new HashMap<String, String>();
        values.put("name", q);
        String name = values.get("name");
        Statement statement = connection.createStatement();
        statement.executeQuery("select * from t where name='" + name + "'");
    }

    @GetMapping("/sql-constant")
    public void sqlConstant(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<String>();
        values.add("trident-fixed");
        String name = values.get(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("select * from t where name='" + name + "'");
    }

    @GetMapping("/command-list")
    public void commandList(@RequestParam("q") String q) throws Exception {
        // fixture:collection-command-list
        List<String> values = new ArrayList<String>();
        values.add(q);
        String name = values.get(0);
        Runtime.getRuntime().exec(name);
    }

    @GetMapping("/command-constant")
    public void commandConstant(@RequestParam("q") String q) throws Exception {
        List<String> values = new ArrayList<String>();
        values.add("trident-fixed");
        Runtime.getRuntime().exec(values.get(0));
    }

    @GetMapping("/xss-list")
    public void xssList(@RequestParam("q") String q, HttpServletResponse response) throws Exception {
        // fixture:collection-xss-list
        List<String> values = new ArrayList<String>();
        values.add(q);
        String name = values.get(0);
        PrintWriter writer = response.getWriter();
        writer.write(name);
    }

    @GetMapping("/dynamic")
    public void dynamic(@RequestParam("q") String q) throws Exception {
        // fixture:collection-dynamic
        List<String> values = new ArrayList<String>();
        values.add(String.format(q));
        String name = values.get(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("select * from t where name='" + name + "'");
    }

    @GetMapping("/unknown-receiver")
    public void unknownReceiver(@RequestParam("q") String q) throws Exception {
        // fixture:collection-unknown-receiver
        SomeStore store = new SomeStore();
        store.add(q);
        String name = store.get(0);
        Statement statement = connection.createStatement();
        statement.executeQuery("select * from t where name='" + name + "'");
    }
}
