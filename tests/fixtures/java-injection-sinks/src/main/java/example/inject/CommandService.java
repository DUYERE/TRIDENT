package example.inject;

public final class CommandService {
    public String run(String value) throws Exception {
        // fixture:command-exec
        return exec(value);
    }

    private String exec(String value) throws Exception {
        Process process = Runtime.getRuntime().exec(value);
        return String.valueOf(process.pid());
    }

    public void runBuilder(String value) throws Exception {
        // fixture:command-builder
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(value);
        builder.start();
    }

    public void runConstant(String value) throws Exception {
        ProcessBuilder builder = new ProcessBuilder();
        builder.command("ls -l");
        builder.start();
    }

    public void runDynamic(String value) throws Exception {
        // fixture:command-dynamic
        Runtime.getRuntime().exec(String.format(value, "x"));
    }
}
