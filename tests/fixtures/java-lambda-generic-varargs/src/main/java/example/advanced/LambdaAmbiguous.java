package example.advanced;

import java.util.function.Consumer;
import java.util.function.Function;

public final class LambdaAmbiguous {
    public String find(Function<String, String> mapper) {
        return "SELECT 1";
    }

    public String find(Consumer<String> consumer) {
        return "SELECT 2";
    }
}
