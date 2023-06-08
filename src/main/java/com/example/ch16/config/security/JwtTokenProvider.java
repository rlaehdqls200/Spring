package com.example.ch16.config.security;

import com.example.ch16.service.UserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final UserDetailService userDetailService;

    private final long tokenValidMilliSecond = 1000L * 60 * 60; //60분
    private String secretKey = "daelimSpring!@#$daelimSpring!@#$daelimSpring!@#$";


    //원래 코드엔 잘 박지 않음
    @PostConstruct
    protected void init() {
        System.out.println("[init] JwtTokenProvider init Start >>>>");
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
        System.out.println("secretKey :"+secretKey);
    }
    public String createToken(String userUid, List<String> roles){
        System.out.println("[createToken 토큰 생성 시작");
        Claims claims = Jwts.claims().setSubject(userUid);
        claims.put("roles",roles);
        Date now = new Date();
        String token = Jwts.builder().setClaims(claims)
                .setIssuedAt(now) //IssuedAt 발급일
                .setExpiration(new Date(now.getTime()+tokenValidMilliSecond)) //Expiration 만료일
                .signWith(SignatureAlgorithm.HS256, secretKey).compact();
        System.out.println("token :" + token);
        return token;
    }
    public Authentication getAuthenication(String token){
        System.out.println("[getAuthenication] 토큰 정보 조회");
        UserDetails userDetails = userDetailService.loadUserByUsername(this.getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails,"", userDetails.getAuthorities());
    }
    public String getUsername(String token){
        String info = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
        System.out.println("[getUsername]" + info);
        return info;
    }
    public String resolveToken(HttpServletRequest request){
        return request.getHeader("X-AUTH-TOKEN"); //프로젝트별로 다르게 설정 가능
        //헤더별로 어떻게 넣어줄지 정하는것 즉, 우리는 헤더에 들어간 위에 이름의 값을 추출한다
    }

    public boolean validateToken(String token){
        try{
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
