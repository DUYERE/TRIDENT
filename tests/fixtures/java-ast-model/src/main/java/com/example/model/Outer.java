package com.example.model;

public class Outer {
    static final String NAME = "outer";

    public String label() {
        return NAME;
    }

    class Inner {
        String describe() {
            return label();
        }
    }
}
