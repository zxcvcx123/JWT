package org.daeng2go.daeng2go_server.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.common.exception.MessageException;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * 업 무 : JwtTokenFactory
 * 설 명 : JwtToken 생성
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@Slf4j
@Component
public class JwtTokenFactory {

    private SecretKey secretKey;

    /* 시크릿 키 생성 */
    public JwtTokenFactory(@Value(value = "${jwt.private.secretkey}")String secret) {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());

    }

    /**
     * @Method	- getIdx
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰에 저장된 사용자 고유값 가져오기
     * @param token 토큰 값
     * @Return	- String 토큰에 저장된 IDX
     */
    public String getIdx(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("idx", String.class);
    }

    /**
     * @Method	- getId
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰에 저장된 사용자아이디 가져오기
     * @param token 토큰 값
     * @Return	- String 토큰에 저장된 ID
     */
    public String getId(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("id", String.class);
    }

    /**
     * @Method	- getName
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰에 저장된 사용자이름 가져오기
     * @param token 토큰 값
     * @Return	- String 토큰에 저장된 사용자이름
     */
    public String getName(String token){

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("name", String.class);
    }


    /**
     * @Method	- getRole
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰에 저장된 role(권한) 가져오기
     * @param token 토큰 값
     * @Return	- String 토큰에 저장된 role(권한)
     */
    public String getRole(String token){

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    /**
     * @Method	- getType
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰 타입 가져오기 refresh, access
     * @param token 토큰 값
     * @Return	- String 토큰에 저장된 타입 refresh, access
     */
    public String getType(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("type", String.class);
    }

    /**
     * @Method	- isExpired
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 토큰 유효시간 체크
     * @param token 토큰 값
     * @Return  - void
     */
    public void isExpired(String token) {

            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration().before(new Date());

    }

    /**
     * @Method	- createAccessToken
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- access 토큰 생성하기 (토큰타입, 아이디, 이름, 권한, 만료시간)
     * @param type 토큰 타입 access
     * @param idx 토큰에 넣을 유저 idx 값
     * @param id 토큰에 넣을 유저 id
     * @param name 토큰에 넣을 유저 name
     * @param role 토큰에 넣을 유저 role(권한)
     * @param expiredSeconds 토큰 만료시간 (단위:초)
     * @Return	- String access 토큰
     */
    public String createAccessToken(String type,String idx, String id, String name, String role, String expiredSeconds){

        // 초 단위로 변환
        Long expiredSetSeconds = Long.parseLong(expiredSeconds);

        return Jwts.builder()
                .claim("type", type)
                .claim("idx", idx)
                .claim("id", id)
                .claim("name", name)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredSetSeconds * 1000L))
                .signWith(secretKey)
                .compact();
    }


    /**
     * @Method	- createRefreshToken
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- refresh 토큰 생성하기 (토큰타입, 아이디, 만료시간)
     * @param type 토큰 타입 refress
     * @param id 토큰에 넣을 유저 id
     * @param expiredSeconds 토큰 만료시간 (단위:초)
     * @Return	- String refresh 토큰
     */
    public String createRefreshToken(String type, String idx, String id, String name, String role, String expiredSeconds){

        // 초 단위로 변환
        Long expiredSetSeconds = Long.parseLong(expiredSeconds);

        return Jwts.builder()
                .claim("type", type)
                .claim("idx", idx)
                .claim("id", id)
                .claim("name", name)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredSetSeconds * 1000L))
                .signWith(secretKey)
                .compact();
    }

    /**
     * @Method - createReIssueRefreshToken
     * @Date - 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- refresh 토큰 생성하기 (토큰타입, 아이디, 만료시간)
     * @param type 토큰 타입 refress
     * @param id 토큰에 넣을 유저 id
     * @param expiredSeconds 토큰 만료시간 (단위:초)
     * @Return	- String refresh 토큰
     */
    public String createReIssueRefreshToken(String type, String id, String expiredSeconds){

        // 초 단위로 변환
        Long expiredSetSeconds = Long.parseLong(expiredSeconds);

        return Jwts.builder()
                .claim("type", type)
                .claim("id", id)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredSetSeconds * 1000L))
                .signWith(secretKey)
                .compact();
    }


}
