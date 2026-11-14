package com.example.reach;

import org.example.lib.LibApi;

// [02] Intermediate class that imports the declared dependency.
public class ReachService {

    public String render() {
        return LibApi.render("fixture");
    }
}
