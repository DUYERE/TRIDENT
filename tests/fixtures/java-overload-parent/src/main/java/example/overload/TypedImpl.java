package example.overload;

public final class TypedImpl implements TypedLookup {
    @Override
    public String find(String name) {
        // [01] fixture:overload-string
        return "SELECT id FROM synthetic_customers WHERE name = '" + name + "'";
    }

    @Override
    public String find(Integer id) {
        return "SELECT id FROM synthetic_customers WHERE id = " + id;
    }
}
