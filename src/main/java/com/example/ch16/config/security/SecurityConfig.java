package com.example.ch16.config.security;

import org.springframework.beans.factory.annotation.CustomAutowireConfigurer;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableGlobalMethodSecurity(
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .httpBasic().disable()
                .csrf().disable()//사이트 요청 위조
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/sign-api/sign-in","/sign-api/sign-up","/sign-api/exception")
                //위 경로로 들어온 애들은 누구에게나 허용한다.(로그인, 회원가입 이런데는 권한이 필요없기 때문)
                .permitAll()
                .antMatchers(HttpMethod.GET,"/user/**").permitAll()
                //http 메서드가 GET인 경우 경로가 product로 시작하는 모든 경로를 허용한다.
                .anyRequest().hasAnyRole("ADMIN","USER") //Any 여부로 복수, 단일 갯수 여부를 선택 가능
                //권한을 가진 사람에게만 허용(어드민)
                .and()
                .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler())
                //CustomAccessDeniedHandler경로에서 예외처리 해준다.
                .and()
                .exceptionHandling().authenticationEntryPoint(new CustomAuthenicationEntryPoint())
                //위와 동일
                .and()
                .addFilterBefore(new JwtAuthenicationFilter(jwtTokenProvider),UsernamePasswordAuthenticationFilter.class);
                //UsernamePasswordAuthenticationFilter 앞에(before) 필터에다가 추가(add)를 한다.
    }

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        webSecurity.ignoring()
                .antMatchers(
                        "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui/index.html",
                                "/swagger/**",
                                "/sign-api/exception");
    }

}
