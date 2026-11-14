package example.upgrade;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class VersionUseTest {
    @Test
    public void substitutesPlaceholder() {
        assertEquals("hello world", VersionUse.render("world"));
    }
}
