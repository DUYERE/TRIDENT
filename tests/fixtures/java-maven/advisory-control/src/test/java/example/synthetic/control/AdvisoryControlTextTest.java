package example.synthetic.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

// [01] Future compatibility check for this benign API, not a CVE exploit test.
class AdvisoryControlTextTest {
    @Test
    @Tag("business")
    void syntheticLabelEscapesMarkup() {
        // [02] Required control test so a no-test module cannot silently be called validated.
        assertEquals("Synthetic &lt;control&gt;", AdvisoryControlText.syntheticLabel());
    }
}
