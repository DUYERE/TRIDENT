package example.dispatch;

public final class OverrideRepo extends BaseRepo {
    @Override
    public String build(String value) {
        return "SELECT id FROM synthetic_customers WHERE alias = '" + value + "'";
    }
}
