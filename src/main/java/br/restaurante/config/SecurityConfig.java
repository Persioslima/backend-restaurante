package br.restaurante.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.restaurante.repository.ClienteRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                    // Swagger (libera acesso público à documentação)
                    .requestMatchers(
                            "/swagger-ui/**",
                            "/v3/api-docs/**",
                            "/api-docs/**",
                            "/swagger-ui.html"
                    ).permitAll()

                    // Páginas e recursos estáticos
                    .requestMatchers("/", "/index.html", "/cadastro.html", "/clientes.html",
                            "/restaurante.html", "/dados.html", "/itens.html", "/avaliacao.html",
                            "/restaurantePerfil.html", "/pedidos.html", "/css/**", "/js/**", "/uploads/**")
                            .permitAll()

                    // Endpoints públicos
                    .requestMatchers("/clientes/**", "/restaurantes/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/itens/**", "/avaliacoes/**", "/avaliacoes-prato/**").permitAll()

                    // Gerenciamento de itens (temporariamente públicos)
                    .requestMatchers(HttpMethod.POST, "/itens/**").permitAll()
                    .requestMatchers(HttpMethod.PUT, "/itens/**").permitAll()
                    .requestMatchers(HttpMethod.DELETE, "/itens/**").permitAll()

                    // Todo o resto requer autenticação
                    .anyRequest().authenticated()
            )
            .formLogin(form -> form
                    .loginProcessingUrl("/login")
                    .permitAll()
            )
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .deleteCookies("JSESSIONID")
                    .invalidateHttpSession(true)
                    .permitAll()
            );

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowCredentials(true);

        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:8081",
                "http://127.0.0.1:8081",
                "http://localhost:3000",
                "http://127.0.0.1:3000"
        ));

        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));

        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin",
                "Access-Control-Request-Method", "Access-Control-Request-Headers"
        ));

        configuration.setExposedHeaders(Arrays.asList(
                "Location", "Content-Disposition", "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));

        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public UserDetailsService userDetailsService(ClienteRepository clienteRepository) {
        return username -> clienteRepository.findByEmail(username)
                .map(cliente -> User.withUsername(cliente.getEmail())
                        .password(cliente.getSenha())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));
    }
}
