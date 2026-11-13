package example.dispatch;

public final class FirstLookup implements Ambiguous {
    @Override
    public String find(String name) {
        return "SELECT id FROM synthetic_customers WHERE id = 1";
    }
}
