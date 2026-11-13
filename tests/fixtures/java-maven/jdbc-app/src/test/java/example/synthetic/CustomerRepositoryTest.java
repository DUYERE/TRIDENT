package example.synthetic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

// [01] Future sandbox material, not an executed acceptance result or an HTTP integration test.
class CustomerRepositoryTest {
    private Connection keeper;
    private CustomerRepository repository;

    @BeforeEach
    void setUp() throws Exception {
        // [02] A fresh, in-memory-only synthetic database; no credentials, files or TCP listener.
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:fixture_" + UUID.randomUUID().toString().replace("-", ""));
        keeper = dataSource.getConnection();
        try (Statement schema = keeper.createStatement()) {
            schema.execute("CREATE TABLE synthetic_customers (id INTEGER PRIMARY KEY, name VARCHAR(100) NOT NULL)");
        }
        try (PreparedStatement insert = keeper.prepareStatement(
                "INSERT INTO synthetic_customers (id, name) VALUES (?, ?)")) {
            // [03] fixture:synthetic-rows; O'Brien covers preservation of literal quote semantics.
            List<Customer> rows = List.of(
                    new Customer(1, "Synthetic Alice"),
                    new Customer(2, "Synthetic Bob"),
                    new Customer(3, "Synthetic O'Brien"));
            for (Customer row : rows) {
                insert.setInt(1, row.id());
                insert.setString(2, row.name());
                insert.executeUpdate();
            }
        }
        repository = new CustomerRepository(dataSource);
    }

    @AfterEach
    void tearDown() throws Exception {
        // [04] Closing the last connection destroys the database (no DB_CLOSE_DELAY override).
        if (keeper != null) {
            keeper.close();
        }
    }

    @Test
    @Tag("business")
    void unsafeExactMatchPreservesBusinessResult() throws Exception {
        // [05] Required on both baseline and repaired copies.
        assertEquals(List.of(new Customer(1, "Synthetic Alice")),
                repository.findByNameUnsafe("Synthetic Alice"));
    }

    @Test
    @Tag("business")
    void unsafeMissingNameReturnsEmpty() throws Exception {
        // [06] A repair must not replace the repository with a constant nonempty result.
        assertEquals(List.of(), repository.findByNameUnsafe("Synthetic Missing"));
    }

    @Test
    @Tag("business")
    void parameterizedExactMatchPreservesBusinessResult() throws Exception {
        // [07] Protected negative-control behavior must not regress.
        assertEquals(List.of(new Customer(2, "Synthetic Bob")),
                repository.findByNameParameterized("Synthetic Bob"));
    }

    @Test
    @Tag("business")
    void parameterizedMissingNameReturnsEmpty() throws Exception {
        // [08] An absent literal is not an error and not a full-table result.
        assertEquals(List.of(), repository.findByNameParameterized("Synthetic Missing"));
    }

    @Test
    @Tag("business")
    void parameterizedQuotedNameRemainsLiteral() throws Exception {
        // [09] Do not "fix" SQL injection by stripping valid quote characters.
        assertEquals(List.of(new Customer(3, "Synthetic O'Brien")),
                repository.findByNameParameterized("Synthetic O'Brien"));
    }

    @Test
    @Tag("security")
    void unsafeTautologyMustRemainLiteral() throws Exception {
        // [10] fixture:baseline-fails-tautology; expect no rows, NOT successful exploitation.
        // The vulnerable baseline is expected to fail this assertion; a repair must pass it.
        assertEquals(List.of(), repository.findByNameUnsafe("' OR '1'='1"));
    }

    @Test
    @Tag("security")
    void unsafeCommentMustRemainLiteral() throws Exception {
        // [11] fixture:baseline-fails-comment; confined to the in-memory synthetic table.
        assertEquals(List.of(), repository.findByNameUnsafe("nobody' OR 1=1 -- "));
    }

    @Test
    @Tag("security")
    void parameterizedTautologyRemainsLiteral() throws Exception {
        // [12] Negative control: identical value must never turn into a SQL predicate.
        assertEquals(List.of(), repository.findByNameParameterized("' OR '1'='1"));
    }
}
