package example.advanced;

public final class GenRepo {
    public <T> T pass(T value) {
        // [03] fixture:generic-identity
        return value;
    }

    public String find(String name) {
        return "SELECT id FROM synthetic_customers WHERE name = '" + name + "'";
    }

    public String find(Integer id) {
        return "SELECT id FROM synthetic_customers WHERE id = " + id;
    }
}
