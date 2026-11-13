package example.synthetic;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.stereotype.Repository;

// [01] Intentionally vulnerable training material; never wire to a production database.
@Repository
public final class CustomerRepository {
    private final DataSource dataSource;

    public CustomerRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public List<Customer> findByNameUnsafe(String name) throws SQLException {
        // [02] fixture:sql-concatenation; attacker-controlled name becomes SQL syntax.
        String sql = "SELECT id, name FROM synthetic_customers WHERE name = '" + name + "' ORDER BY id";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             // [03] fixture:jdbc-concat-sink; preserve this query's semantics when repairing.
             ResultSet rows = statement.executeQuery(sql)) {
            return readCustomers(rows);
        }
    }

    public List<Customer> findByNameParameterized(String name) throws SQLException {
        // [04] fixture:parameterized-query; negative control for CWE-89 on this value input.
        String sql = "SELECT id, name FROM synthetic_customers WHERE name = ? ORDER BY id";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            // [05] fixture:jdbc-value-binding; no dynamic table, column or ordering input.
            statement.setString(1, name);
            try (ResultSet rows = statement.executeQuery()) {
                return readCustomers(rows);
            }
        }
    }

    private static List<Customer> readCustomers(ResultSet rows) throws SQLException {
        // [06] Consume rows before closing JDBC resources; SQL errors are not swallowed.
        List<Customer> customers = new ArrayList<>();
        while (rows.next()) {
            customers.add(new Customer(rows.getInt("id"), rows.getString("name")));
        }
        return List.copyOf(customers);
    }
}
