package example.synthetic;

import java.sql.SQLException;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// [01] Route-discovery material only: no server, boot entry point or deployment configuration.
@RestController
@RequestMapping("/synthetic/customers")
public final class CustomerController {
    private final CustomerRepository repository;
    private final DynamicCustomerLookup dynamicLookup;

    public CustomerController(CustomerRepository repository, DynamicCustomerLookup dynamicLookup) {
        this.repository = repository;
        this.dynamicLookup = dynamicLookup;
    }

    @GetMapping("/unsafe")
    public List<Customer> unsafe(@RequestParam("name") String name) throws SQLException {
        // [02] fixture:unsafe-http-source; direct bounded cross-file path to JDBC concatenation.
        return repository.findByNameUnsafe(name);
    }

    @GetMapping("/parameterized")
    public List<Customer> parameterized(@RequestParam("name") String name) throws SQLException {
        // [03] fixture:safe-http-source; input reaches setString, not a SQL fragment.
        return repository.findByNameParameterized(name);
    }

    @GetMapping("/dynamic")
    public Object dynamic(@RequestParam("name") String name) throws ReflectiveOperationException {
        // [04] fixture:dynamic-http-source; unknown target is not proof of safety or a SQL sink.
        return dynamicLookup.findByName(name);
    }
}
