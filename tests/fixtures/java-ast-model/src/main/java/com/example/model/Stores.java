package com.example.model;

interface Store {
    void save(String value);
}

class JdbcStore implements Store {
    public void save(String value) {
    }
}

class StoreClient {
    void persist(Store store, String value) {
        store.save(value);
    }
}

interface Handler {
    void handle(String value);
}

class AlphaHandler implements Handler {
    public void handle(String value) {
    }
}

class BetaHandler implements Handler {
    public void handle(String value) {
    }
}

class HandlerClient {
    void run(Handler handler, String value) {
        handler.handle(value);
    }
}
