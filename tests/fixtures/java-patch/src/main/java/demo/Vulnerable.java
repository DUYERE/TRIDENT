package demo;

public final class Vulnerable {
    private Vulnerable() {
    }

    public static String query(String name) {
        return "SELECT * FROM users WHERE name='" + name + "'";
    }

    public static boolean isSafe(String name) {
        String sql = query(name);
        return sql.contains("?") && !sql.contains(name);
    }
}
