package example.advanced;

import java.util.function.Function;

public final class LambdaRepo {
    public String find(Function<String, String> mapper) {
        // [01] fixture:lambda-overload
        return "SELECT id FROM synthetic_customers WHERE name = '" + mapper.apply("x") + "'";
    }

    public String find(Integer id) {
        return "SELECT id FROM synthetic_customers WHERE id = " + id;
    }
}
