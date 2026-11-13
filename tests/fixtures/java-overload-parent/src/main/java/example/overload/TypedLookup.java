package example.overload;

public interface TypedLookup {
    String find(String name);

    String find(Integer id);
}
