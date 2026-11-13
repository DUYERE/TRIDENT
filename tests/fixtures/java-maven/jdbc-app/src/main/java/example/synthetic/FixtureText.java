package example.synthetic;

import org.apache.commons.text.StringEscapeUtils;

// [01] An unrelated Commons Text call does not prove a StringSubstitutor exploit path.
public final class FixtureText {
    private FixtureText() {
    }

    public static String syntheticLabel() {
        // [02] fixture:candidate-benign-call; no untrusted interpolation or execution payload.
        return StringEscapeUtils.escapeHtml4("Synthetic <customer>");
    }
}
