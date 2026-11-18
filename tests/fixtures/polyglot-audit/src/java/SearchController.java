package demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SearchController {

    @GetMapping("/search")
    public String search(@RequestParam("name") String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForObject(sql, String.class);
    }

    @PostMapping("/exec")
    public String exec(@RequestBody String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        return "ok";
    }

    @GetMapping("/safe")
    public String safe(@RequestParam("id") String id) {
        // 负例：预编译语句与参数绑定
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return "ok";
    }

    @PostMapping("/legacy")
    public void legacy(@RequestBody byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        ois.readObject();
    }

    // jdbcTemplate.queryForObject(request.getParameter("id"));
    // Runtime.getRuntime().exec(request.getHeader("cmd"));
    private static final String NOTE = "Runtime.getRuntime().exec(cmd)";
}

// 正例（v2）：开放重定向
response.sendRedirect(request.getParameter("goto"));
