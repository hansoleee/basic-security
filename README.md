# 스프링 시큐리티 - Spring Boot 기반으로 개발하는 Spring Security
- - - 
## 시작일 2021.08.07
- - - 
## 학습 내용
### 스프링 시큐리티 기본 API 및 Filter 이해
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
- - - 
### 스프링 시큐리티 주요 아키텍처 이해
#### 2021.08.08 1) 위임 필터 및 필터 빈 초기화 - DelegatingProxyChain, FilterChainProxy
- Servlet Filter의 역할
> Servlet Filter는 사용자의 요청과 Servlet 사이에 위치하여    
> 사용자의 요청을 받아 작업을 수행하고 Servlet으로 전달하는 역할과   
> Servlet에서 사용자의 요청을 처리한 결과에 대한 추가 작업을 수행하고 사용자에게 전달하는 역할을 수행함
- Servlet Container에서 관리하는 Servlet Filter는 Spring Container에서 관리하는 Bean을 주입할 수 없음
> DelegatingFilterProxy를 이용하여 Spring Container에서 관리하는 Bean(springSecurityFilterChain)에 요청을 위임하여 Filter 처리를 할 수 있음   
> ~~밎니?~~ DelegatingFilterProxy과 springSecurityFilterChain은 꼭 다시 찾아서 공부해야함
- 사용자 정의 필터를 생성해서 기존 필터 순서들 사이에 추가 가능함

#### 2021.08.11 2) 필터 초기화와 다중 보안 설정
- WebSecurityConfigurerAdapter를 상속한 여러개의 Bean을 생성할 수 있음
> @Order(n) (n >= 0)를 통해 여러개의 Bean을 등록할 수 있음   
> antMatchers()의 우선 순위를 고려해서 설계해야함   

#### 2021.08.11 3) 인증 개념 이해 - Authentication
- Authentication의 개념
> 1.사용자가 누구인지 증명하는 것   
> 2.인증할 때 id와 password를 담고 인증 검증을 위해 사용됨   
> 3.인증을 마친 뒤 인증 결과 (User 객체, 권한 정보)를 담고 SecurityContext에 저장되어 전역적으로 참조 가능   
> ```java
> Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
> ```
> 4.구조   
> - principal : 사용자 아이디 또는 User 객체   
> - credentials : 사용자 비밀번호   
> - authorities : 인증된 사용자의 권한 목록   
> - details : 인증 부가 정보   
> - authenticated : 인증 여부   
- Authentication 객체가 인증 흐름에 사용되어지는 과정
- Authentication 생성자의 종류
> principal와 credentials를 매개변수로 받는 생성자와 prinipal과 credentials, authorities를 매개변수로 받는 생성자가 있음

#### 2021.08.11 4) 인증 저장소 - SecurityContextHolder, SecurityContext
- SecurityContext 객체의 역할
> SecurityContext 객체는 Authentication 객체를 저장하는 역할을 수행함   
- ThreadLocal의 개념
> ThreadLocal은 Thread 내부에서 사용하는 지역변수를 갖고있는 객체   
> get(), set(), remove() API 를 지원함   
- SecurityContextHolder 객체의 개념과 역할
> SecurityContext를 감싸는 객체   
- SecurityContext를 감싸는 3가지 방식
> 1.MODE_THREADLOCAL : 스레드당 SecurityContext 객체를 할당, 기본값
> 2.MODE_INHERITABLETHREADLOCAL : 메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext를 유지
> 3.MODE_GLOBAL : 응용 프로그램에서 단 하나의 SecurityContext 기존 정보 초기화
- SecurityContext 초기화 방법
```java
SecurityContextHolder.clearContext();
```

#### 2021.08.12 5) 인증 저장소 필터 - SecurityContextPersistenceFilter
- SecurityContextPersistenceFilter의 역할
> SecurityContext 객체의 생성, 저장, 조회를 담당하는 Filter 객체   
> 1.익명 사용자   
> 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장   
> AnonymousAuthenticationFilter에서 AnonymousAuthenticationToken 객체를 SecurityContext에 저장   
> 2.인증을 수행할 때    
> 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장   
> UsernamePasswordAuthenticationFilter에서 인증 성공 후 SecurityContext에 UsernamePasswordAuthentication Token 객체를 SecurityContext에 저장   
> 인증이 최종 완료되면 Session에 SecurityContext를 저장   
> 3.인증을 받은 경우     
> Session에서 SecurityContext를 꺼내고 SecurityContextHolder에서 저장   
> SecurityContext 안에 Authentication 객체가 존재하면 계속 인증을 유지   
> 4.최종 응답 후    
> SecurityContextHolder.clearContext(); 를 수행

#### 2021.08.12 6) 인증 흐름 이해 - Authentication Flow
- 인증에 대한 처리 과정과 각 과정에 사용되는 객체에 대한 이해

#### 2021.08.13 7) 인증 관리자: AuthenticationManager
- ProviderManager의 처리 과정
> 만약 ProviderManager에 인증 요청을 처리할 Provider가 존재하지 않는다면   
> parent ProviderManager에서 인증을 처리할 수 있는 Provider를 찾고 인증 처리를 수행함

#### 2021.08.13 8) AuthenticationProvider
- AuthenticationProvider의 역할
> 인증 처리에 가장 핵심적인 역할을 담당

#### 2021.08.14 9) 인가 개념 및 필터 이해: Authorization, FilterSecurityInterceptor
- Authorization의 의미
> Authorization(인가)은 요청이 허가되었는지 확인하는 것
- Spring Security가 지원하는 권한 계층
> 1.웹 계층   
> URL 요청에 따른 메뉴 또는 화면 단위의 레벨 보안   
> 2.서비스 계층   
> 화면 단위가 아닌 메소드 같은 기능 단위의 레벨 보안   
> 3.도메인 계층(Access Control List, 접근 제어 목록)   
> 객체 단위의 레벨 보안   
- FilterSecurityInterceptor의 역할
> 마지막에 위한 필터로써 인증된 사용자에 대하여 특정 요청의 승인/거부 여부를 최종적으로 결정함   
> 인증 객체 없이 보호 자원에 접근을 시도하는 경우 AuthenticationException을 발생함   
> 인증 후 자원에 접근 가능한 권한이 존재하지 않을 경우 AccessDeniedException을 발생함   
> 권한 제어 방식 중 HTTP 자원의 보안을 처리하는 필터   
> 권한 처리를 AccessDecisionManager에게 위임함   

#### 2021.08.14 10) 인가 결정 심의자 - AccessDecisionManager, AccessDecisionVoter
- AccessDecisionManager의 역할
> 인증 정보, 요청 정보, 권한 정보를 이용해서 사용자의 자원 접근을 허용할 것인지 거부할 것인지 최종 결정하는 주체   
> 여러 개의 Voter들을 가질 수 있으며 Voter들로부터 접근 허용, 거부, 보류에 해당하는 각각의 값을 리턴받고 판단 및 결정   
> 최종 접근 거부 시 예외 발생
- 접근 결정의 3가지 유형
> 1.AffirmativeBased: 여러 개의 Voter 클래스 중 하나라도 접근 허가로 결론을 내면 접근 허가로 판단   
> 2.ConsensusBased: 다수표(승인 및 거부)에 의해 최종 결정을 판단      
> 승인/거부 표가 같을 경우 기본 접근 허가이나 allowIfEqualGrantedDeniedDecisions을 False로 설정할 경우 접근 거부 가능함   
> 3.UnanimousBased: 만장일치가 될 경우만 접근 허가로 판단   
- AccessDecisionVoter의 역할
>1.판단을 심사 (위원)   
> 2.Voter가 권한 부여 과정에서 판단하는 자료   
> Authentication - 인증 정보 (ROLE_USER)   
> FilterInvocation - 요청 정보 (antMatcher("/user"))   
> ConfigAttributes - 권한 정보 (hasRole("USER"))   
> 3.결정 방식   
> ACCESS_GRANTED : 접근 허용 (1)   
> ACCESS_DENIED : 접근 거부 (-1)   
> ACCESS_ABSTAIN : 접근 보류 (0)   

#### 2021.08.14 11) Spring Security Filter 및 Architecture 정리
- 익명 사용자가 인증 요청을 보낸 경우 인증 처리 과정
- 이미 인증된 사용자가 리소스 요청을 보낸 경우 인증 처리 과정
- 이미 인증된 객체가 존재하고 같은 사용자 정보로 새로운 인증 요청을 보낸 경우 인증 처리 과정

### 실전 프로젝트 - 인증 프로세스 Form 인증 구현
#### 2021.08.14 1) 실전 프로젝트 생성
> 다음 강의 부터는 새로운 프로젝트를 만들어 진행함

[core-spring-security](https://github.com/hansoleee/core-spring-security.git "core-spring-security")








