package example.inject;

import java.net.URL;

public final class SsrfService {
    private final RestTemplate restTemplate = new RestTemplate();

    public void fetch(String target) throws Exception {
        // fixture:ssrf-url
        URL url = new URL(target);
        url.openConnection();
    }

    public void fetchRest(String target) {
        // fixture:ssrf-rest
        restTemplate.getForObject(target, String.class);
    }

    public void fetchConstant(String target) throws Exception {
        URL url = new URL("https://example.invalid/health");
        url.openConnection();
    }
}
