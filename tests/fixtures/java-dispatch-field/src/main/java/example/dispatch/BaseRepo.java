package example.dispatch;

public class BaseRepo {
    protected String inherited;

    public String build(String value) {
        // [02] fixture:inherited-method
        return "SELECT id FROM synthetic_customers WHERE name = '" + value + "'";
    }

    public String readInherited() {
        // [03] fixture:inherited-field-read
        return this.inherited;
    }
}
