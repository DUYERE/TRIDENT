package demo;

import java.util.List;

public interface UserMapper {
    List<User> findByName(String name);

    List<User> orderBy(String column);

    int rename(String name, int id);
}
