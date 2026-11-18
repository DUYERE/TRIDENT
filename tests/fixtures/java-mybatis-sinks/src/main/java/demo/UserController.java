package demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserMapper userMapper;

    @GetMapping("/find")
    public String find(@RequestParam("name") String name) {
        // 参数绑定：UserMapper.xml 中 findByName 只有 #{name}
        return userMapper.findByName(name).toString();
    }

    @GetMapping("/order")
    public String order(@RequestParam("column") String column) {
        // 字符串替换：UserMapper.xml 中 orderBy 使用 ${column}
        return userMapper.orderBy(column).toString();
    }
}
