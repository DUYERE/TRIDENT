package demo;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        if (System.getenv("TRIDENT_MODEL_API_KEY") != null || System.getenv("TRIDENT_DATABASE_URL") != null) {
            System.err.println("host secret leaked into validation process");
            System.exit(2);
        }
        String input = "x' OR '1'='1";
        if (!Vulnerable.isSafe(input)) {
            System.err.println("injection guard missing");
            System.exit(1);
        }
        System.out.println("safe");
    }
}
