package com.hansoleee.basicsecurity.config.security;

import com.hansoleee.basicsecurity.config.security.custom.CustomAuthenticationFailureHandler;
import com.hansoleee.basicsecurity.config.security.custom.CustomAuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.servlet.http.HttpSession;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}a").roles("USER");
        auth.inMemoryAuthentication().withUser("system").password("{noop}a").roles("SYSTEM");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}a").roles("ADMIN");
        auth.inMemoryAuthentication().withUser("all").password("{noop}a").roles("ADMIN", "SYSTEM", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()

                .and()
                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/login"))
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"))

                .and()
                .authorizeRequests()
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/system/**").hasRole("SYSTEM")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()

                .and()
                .formLogin()
//                .loginPage("/login") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("email") // 아이디 파라미터명 설정
                .passwordParameter("password") // 패스워드 파라미터명 설정
//                .loginProcessingUrl("/login") // 로그인 Form Action Url
                .successHandler(customAuthenticationSuccessHandler) // 로그인 성공 후 핸들러 (권장 방식)
                .failureHandler(customAuthenticationFailureHandler) // 로그인 실패 후 핸들러 (권장 방식)
                .permitAll()

                .and()
                .logout() // 로그아웃 처리
                .logoutUrl("/logout") // 로그아웃 처리 URL
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 페이지
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 성공 후 쿠키 삭제
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                }) // 로그아웃 핸들러
                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login")) // 로그아웃 성공 후 핸들러
                .permitAll()

                .and()
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명: remember-me
                .tokenValiditySeconds(3600) // Default: 14days
                .alwaysRemember(false) //Remember Me 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService)

                .and()
                .sessionManagement()
                .sessionFixation().changeSessionId() // 기본값
//                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 세션 생성 정책
                .maximumSessions(1) // 허용 세션 최대 개수
                .maxSessionsPreventsLogin(false) // true: 새로운 세션 허용 안함, false: 새로운 세션 허용
                .expiredUrl("/expired") // 세션 만료 후 이동 페이지
        ;
    }
}
