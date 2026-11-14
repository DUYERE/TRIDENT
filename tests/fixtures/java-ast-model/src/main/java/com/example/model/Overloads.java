package com.example.model;

import java.util.List;

public class Overloads {
    public String pick(String value) {
        return value;
    }

    public String pick(List<String> values) {
        return values.get(0);
    }

    public String use(String text, List<String> items) {
        String first = pick(text);
        String second = pick(items);
        return first + second;
    }
}
