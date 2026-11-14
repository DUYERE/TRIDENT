package com.example.model;

@interface Route {
    String value();

    String[] tags() default {};
}

@interface Access {
    Role value();
}

enum Role {
    ADMIN,
    USER
}

public class Annotated {
    static final String PREFIX = "api";
    static final int LIMIT = 2 + 3;

    @Route(value = PREFIX + "/items", tags = {PREFIX, "read"})
    public void list() {
    }

    @Access(Role.ADMIN)
    public void admin() {
    }
}
