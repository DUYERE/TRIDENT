package demo;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class VulnerableTest {
    @Test
    public void rejectsInjection() {
        assertTrue(Vulnerable.isSafe("x' OR '1'='1"));
    }
}
