package example.upgrade;

import java.util.Collections;

import org.apache.commons.text.StringSubstitutor;

public class VersionUse {
    public static String render(String name) {
        StringSubstitutor substitutor = new StringSubstitutor(Collections.singletonMap("name", name));
        return substitutor.replace("hello ${name}");
    }
}
