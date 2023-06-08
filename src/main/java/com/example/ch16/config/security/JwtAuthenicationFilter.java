package com.example.ch16.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//GenericFilterBean : 기존 필터에서 가져올 수 없는 스프링의 설정 정보를
// 가져올 수 있게 확장된 추상 클래스로 사용자의 요청을 받으면 메모리에 저장해두고
// 동일한 클라이언트의 요청을 받으면 재활용하는 구조여서 필터가 2번 실행되는 현상 발생할 수 있다.
//OncePerRequestFilter가 위의 문제를 해결하기 위해 등장한 필터로 요청마다 한 번만 실행되게끔 구현
public class JwtAuthenicationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenicationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = jwtTokenProvider.resolveToken(request); //request에 헤더에 있는 토큰을 추출해서
        //벨리드에 있는걸 체크해서 유효할시 주는 구문
        System.out.println("[doFilterInternal] token : "+ token);
        if(token != null && jwtTokenProvider.validateToken(token)){
            Authentication authentication = jwtTokenProvider.getAuthenication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } //이 if문 경로로 요청을 받아서 토큰을 체크한후 authentication를 주는 핵심 구문
        filterChain.doFilter(request, response);
    }
}
