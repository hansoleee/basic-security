# 스프링 시큐리티 - Spring Boot 기반으로 개발하는 Spring Security
- - - 
## 시작일 2021.08.07
- - - 
## 학습 내용
#### 2021.08.07 1)프로젝트 구성 및 의존성 추가
> Spring Security 의존성 사용시 웹 서버의 변화 (Default 설정의 경우)
> 1. 모든 요청은 인증되어야 자원에 접근 가능
> 2. 기본 로그인 페이지를 제공
> 3. 기본 로그인 계정 제공 (ID: user, Password: {Random 값을 Console에 출력})
- Spring Security 의존성을 추가하고 서버의 resource에 접근하면 Spring Security에서 기본 제공하는 Login 페이지로 연결됨
- 로그인 방식은 Form 방식과 HttpBasic 방식을 제공함

#### 2021.08.07 2)사용자 정의 보안 기능 구현
#### 2021.08.07 3)Form Login 인증
- 로그인에 성공 또는 실패하게 되면 처리를 위한 2가지 API를 제공함
> 로그인 성공을 처리하는 API   
> 1.successHandler()   
> 2.defaultSuccessUrl()
> - - - 
> 만약 successHandler()와 defaultSuccessUrl()를 같이 사용하게 되면 successHandler()를 먼저 처리한 후 defaultSuccessUrl()을 처리함   
> successHandler()와 defaultSuccessUrl() 대표적이 차이는   
> successHandler()는 로그인 성공했을 때 사용자 로직을 추가할 수 있고,   
> defaultSuccessUrl()은 로그인이 성공하면 매개변수로 주어진 url을 호출함

> 로그인 실패를 처리하는 API   
> 1.failureHandler()   
> 2.failureUrl()   

사용 방식은 다음 코드를 참고
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()

                .and()
                .formLogin()
//                .loginPage("/login")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home")         // 로그인 성공 후 이동 페이지
                .failureUrl("/login")               // 로그인 실패 후 이동 페이지
                .usernameParameter("email")         // 아이디 파라미터명 설정
                .passwordParameter("password")      // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login")       // 로그인 Form Action Url
                .successHandler((request, response, authentication) -> {
                    log.info("authentication.getName() = " + authentication.getName());
                    response.sendRedirect("/");
                })                                  // 로그인 성공 후 핸들러 (권장 방식)
                .failureHandler((request, response, exception) -> {
                    log.info("exception: {}", exception.getMessage());
                    response.sendRedirect("/login");
                })                                  // 로그인 실패 후 핸들러 (권장 방식)
                .permitAll();
    }
```

#### 2021.08.07 4)Form Login 인증 필터 : UsernamePasswordAuthenticationFilter
- SecurityContextHolder.getContext().getAuthentication()에 Authentication 정보를 저장하는 과정

#### 2021.08.08 5)Logout 처리, LogoutFilter
- 로그아웃 처리 과정
> 1.Client는 Server로 로그아웃 요청("/logout")을 보냄   
> 2.Server는 Client의 요청을 받아 로그아웃 처리 로직을 수행함   
- 로그아웃 처리 로직
> 1.세션 무효화   
> 2.인증 토큰 삭제   
> 3.쿠키 정보 삭제   
> 4.로그인 페이지로 리다이렉트   
- 로그아웃 API
- Spring Security는 기본적으로 POST 방식을 통해 Logout 처리를 수행함
- Logout Filter

#### 2021.08.08 6)Remember Me 인증
- Remember Me 기능 설명과 라이프 사이클
- Remember Me API
- Remember Me 기능을 사용하기 위해서는 반드시 userDetailsService를 설정해야함

#### 2021.08.08 7)Remember Me 인증 필터: RememberMeAuthenticationFilter
- Remember Me Filter가 동작하는 2가지 경우
> 1.SecurityContext에 Authenticatioin 객체가 null일 경우   
> 2.Remember Me 쿠키를 가지고 접속을 시도한 경우
- Remember Me Service의 구현체는 2가지가 있음
> 1.TokenBasedRememberMeServices - Memory 저장 방식을 사용   
> 2.PersistentTokenBasedRememberMeServices - DB 저장 방식을 사용   

#### 2021.08.08 8) 익명사용자 인증 필터: AnonymousAuthenticationFilter
- AnonymousAuthenticationFilter 의 역할
> 인증받지 않은 사용자의 Authentication 객체를 생성함
 
#### 2021.08.08 9) 동시 세션 제어, 세션 고정 보호, 세션 정책
- 동시 세션 제어 2가지 방식의 이해
> 1.이전 사용자 세션 만료   
> 2.현재 사용자 인증 실패   
- 동시 세션 제어 API
- 세션 고정 보호 개념과 방법
- 세션 생성 정책

#### 2021.08.08 10) 세션 제어 필터: SessionManagementFilter, ConcurrentSessionFilter
- SessionManagementFilter와 ConcurrentSessionFilter는 동시 세션 제어를 위해 연계됨
- UsernamePasswordAuthenticationFilter, ConcurrentSessionFilter, RegisterSessionAuthenticationStrategy, ChangeSessionIdAuthenticationStrategy, ConcurrentSessionControlAuthenticationStrategy 의 처리 과정

#### 2021.08.08 11) 권한 설정과 표현식
- 인가 API
- 인가 API 권한 설정 2가지 방식
> 1.선언적 방식   
> 2.동적 방식 - DB 이용 방식   
> - URL
> ```java
> http
>   .antMatchers("/users/profile").hasRole("USER")
>   .antMatchers("/users/**").hasRole("USER");
> ```
> ```text
> antMatchers() 설정할 때 구체적인 경로("/users/profile")를 먼저 설정하고 와일드카드 경로("/users/**")를 나중에 설정해야함
> ```
> - Method
> ```java
> @PreAuthorize("hasRole('USER')")
> public void user() {System.out.println("user");}
> ```
- 인가 API - 표현식
> 인가 API - 표현식에서 hasRole()과 hasAuthority()의 차이   
> hasRole() 사용법: hasRole("USER")   
> hasAuthority() 사용법: hasAuthority("ROLE_USER")   
> hasRole()의 경우 prefix "ROLE_"를 반드시 붙이지 않고 사용해야함   
> hasAuthority()의 경우 prefix "ROLE_"를 반드시 붙여 사용해야함

#### 2021.08.08 12) 예외 처리 및 요청 캐시 필터: ExceptionTranslationFilter, RequestCacheAwareFilter
- ExceptionTranslationFilter의 역할
> ExceptionTranslationFilter는 2가지 예외 처리를 담당함   
> 1.AuthenticationException   
> 2.AccessDeniedException   

#### 2021.08.08 13) 사이트 간 요청 위조 - CSRF, CsrfFilter
- CSRF 원리