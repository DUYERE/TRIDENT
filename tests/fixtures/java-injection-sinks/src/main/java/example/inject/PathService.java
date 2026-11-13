package example.inject;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class PathService {
    public void read(String name) throws Exception {
        // fixture:path-stream
        FileInputStream stream = new FileInputStream(name);
        stream.close();
    }

    public void readFiles(String name) throws Exception {
        // fixture:path-files
        Files.readAllBytes(Paths.get(name));
    }

    public void readConstant(String name) throws Exception {
        Files.readAllBytes(Paths.get("/tmp/trident-fixed.txt"));
    }
}
