package demo;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SecurityConfig {
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/api/private/**").authenticated();
    }
}
