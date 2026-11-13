package example.advanced;

public final class VarRepo {
    public String join(String prefix, String... values) {
        // [02] fixture:varargs-overload
        return "SELECT id FROM synthetic_customers WHERE name = '" + prefix + values[0] + "'";
    }

    public String join(String prefix, Integer... values) {
        return "SELECT id FROM synthetic_customers WHERE id = " + values[0];
    }
}
