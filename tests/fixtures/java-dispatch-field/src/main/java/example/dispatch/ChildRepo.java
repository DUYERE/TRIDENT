package example.dispatch;

public final class ChildRepo extends BaseRepo {
    public void save(String value) {
        // [04] fixture:inherited-field-write
        this.inherited = value;
    }
}
