package example.overload;

public final class TypedRepo {
    public String find(String name) {
        return "SELECT id FROM synthetic_customers WHERE name = '" + name + "'";
    }

    public String find(Integer id) {
        return "SELECT id FROM synthetic_customers WHERE id = " + id;
    }
}
