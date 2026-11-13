package example.dispatch;

public final class JdbcLookup implements Lookup {
    @Override
    public String find(String name) {
        // [01] fixture:interface-dispatch
        return "SELECT id FROM synthetic_customers WHERE name = '" + name + "'";
    }
}
