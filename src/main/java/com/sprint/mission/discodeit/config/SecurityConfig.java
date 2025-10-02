package com.sprint.mission.discodeit.config;

import com.sprint.mission.discodeit.auth.HttpStatusReturningLogoutSuccessHandler;
import com.sprint.mission.discodeit.auth.LoginFailureHandler;
import com.sprint.mission.discodeit.auth.LoginSuccessHandler;
import com.sprint.mission.discodeit.config.handler.SpaCsrfTokenRequestHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/*
 * POST /api/auth/login
 * ↓
 * UsernamePasswordAuthenticationFilter
 * ↓
 * AuthenticationManager (ProviderManager)
 * ↓
 * DiscodeitUserDetailsService.loadUserByUsername()
 * ↓
 * DiscodeitUserDetails 생성 + 비밀번호 검증
 * ↓
 * Authentication 성공 → SecurityContextHolder 저장
 * ↓
 * LoginSuccessHandler.onAuthenticationSuccess() 호출
 */

@Configuration
@EnableWebSecurity(debug = true) // TODO: 운영에서 제외
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           LoginSuccessHandler loginSuccessHandler,
                                           LoginFailureHandler loginFailureHandler,
                                           HttpStatusReturningLogoutSuccessHandler logoutSuccessHandler) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // csrf 토큰 저장소를 쿠키로 지정
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()) // csrf 토큰을 읽고 검증하기 위해 사용
                )
                .formLogin(login -> login
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler(loginSuccessHandler)
                        .failureHandler(loginFailureHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                .authorizeHttpRequests(auth -> auth // URL 별로 접근 권한 설정
                        .requestMatchers("/api/auth/csrf-token").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .requestMatchers("/api/auth/login", "/api/auth/logout").permitAll()
                        .requestMatchers("/swagger-ui/**", "/actuator/**").permitAll()
                        .anyRequest().authenticated() // 그 외에 모든 요청 인증
                )
        ;
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
