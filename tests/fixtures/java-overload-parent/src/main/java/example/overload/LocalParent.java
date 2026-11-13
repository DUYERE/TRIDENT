package example.overload;

public class LocalParent extends com.example.MissingBase {
    public String build(String value) {
        // [03] fixture:local-parent
        return "SELECT id FROM synthetic_customers WHERE name = '" + value + "'";
    }
}
