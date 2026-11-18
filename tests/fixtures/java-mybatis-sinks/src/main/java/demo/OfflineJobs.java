package demo;

import java.io.FileInputStream;
import java.io.ObjectInputStream;

// 没有任何 HTTP 注解：旧引擎完全不会分析这个类。
public class OfflineJobs {

    public static void main(String[] args) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(args[0]));
        Object payload = in.readObject();
        System.out.println(payload);
    }

    public void scheduled(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
