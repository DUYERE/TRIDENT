package demo;

import org.apache.ibatis.annotations.Select;

public interface AnnotatedMapper {

    @Select("SELECT * FROM users WHERE name = '${name}'")
    String unsafe(String name);

    @Select("SELECT * FROM users WHERE id = #{id}")
    String safe(String id);
}
