package example.synthetic;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

// [01] External handler source/configuration is intentionally absent from the fixture.
@Component
public final class DynamicCustomerLookup {
    private final String handlerClassName;

    public DynamicCustomerLookup(@Value("${fixture.lookup.class}") String handlerClassName) {
        this.handlerClassName = handlerClassName;
    }

    public Object findByName(String name) throws ReflectiveOperationException {
        // [02] fixture:dynamic-target; configured class is not controlled by the HTTP parameter.
        Class<?> handler = Class.forName(handlerClassName);
        // [03] fixture:dynamic-invocation; missing public static handler prevents a closed call graph.
        return handler.getMethod("findByName", String.class).invoke(null, name);
    }
}
