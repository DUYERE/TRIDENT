package chain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class ChainConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new AuditFilter(), UsernamePasswordAuthenticationFilter.class)
                .securityMatcher("/chain/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/chain/api/public/**").permitAll()
                        .requestMatchers("/chain/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> {
            auth.anyRequest().permitAll();
        });
        return http.build();
    }
}
