package org.daeng2go.daeng2go_server.jwt.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.common.util.redis.RedisUtil;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.jwt.JwtTokenFactory;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;


/**
 * 업 무 : LogoutFilter 클래스
 * 설 명 : Logout 처리 등등...
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-04   		최초작성
 */
@Slf4j
@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JwtTokenFactory jwtTokenFactory;

    private final RedisUtil redisUtil;

    /**
     * @Method	- doFilter
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그아웃 요청을 시큐리티 필터로 넘겨주는 메소드
     * @param request request 요청
     * @param response response 응답
     * @param chain
     * @Return	- void
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);

    }

    /**
     * @Method	- doFilter
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그아웃 요청시 refresh 토큰 관련 유효성 검증 처리
     * @param request request 요청
     * @param response response 응답
     * @param filterChain
     * @Return	- void
     */
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 응답의 콘텐츠 유형 및 문자 인코딩 설정
        response.setContentType("application/json; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        
        // 모든 path에 logout이 있는 경우
        String requestUri = request.getRequestURI();
        if (!requestUri.matches("^\\/logout$")) {

            filterChain.doFilter(request, response);
            return;
        }

        String requestMethod = request.getMethod();

        // Post 요청 검증
        if (!requestMethod.equals("POST")) {

            filterChain.doFilter(request, response);
            return;
        }

        // request 요청에서 refresh 토큰 값 가져오기
        String refreshToken = null;

        refreshToken = request.getHeader("X-RefreshToken");

        log.info(" ========== 로그아웃 | 리프레시 토큰: " + refreshToken + " ========== ");


        // refresh 토큰이 비어있는지 체크 (비어있어도 로그아웃)
        if (refreshToken == null) {

            // 헤더에 담긴 refresh, access 토큰 모두 삭제처리
            response.setHeader("Authorization", "");
            response.setHeader("X-RefreshToken", "");
            response.setStatus(HttpServletResponse.SC_OK);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s",
                            "data":%s
                        }
                        """, ResponseUtils.S0001, ResponseUtils.S0001_MSG, null);

            response.getWriter().write(responseBody);
            return;
        }

        // refresh 토큰 유효시간 체크 (만료된 refresh 토큰오면 로그아웃 처리)
        try {
            jwtTokenFactory.isExpired(refreshToken);
        } catch (SignatureException se){

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0002, "토큰 위조를 감지했습니다. 추적 시작", null);

            response.getWriter().write(responseBody);
            log.error(" ========== 토큰 위조 감지!!! ========== ");
            return;

        } catch (ExpiredJwtException e) {

            // 헤더에 담긴 refresh, access 토큰 모두 삭제처리
            response.setHeader("Authorization", "");
            response.setHeader("X-RefreshToken", "");
            response.setStatus(HttpServletResponse.SC_OK);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s",
                            "data":%s
                        }
                        """, ResponseUtils.S0001, ResponseUtils.S0001_MSG, null);

            response.getWriter().write(responseBody);
            return;
        } catch (MalformedJwtException me){
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0008, ResponseUtils.U0008_MSG, null);

            response.getWriter().write(responseBody);

            return;
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtTokenFactory.getType(refreshToken);
        if (!category.equals("refresh")) {

            // 응답
            response.setStatus(HttpStatus.OK.value());

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0007, ResponseUtils.U0007_MSG);

            response.getWriter().write(responseBody);
            return;
        }

        log.info(" ========= logoutFilter 통과 ");
        // 로그아웃 진행

        // 헤더에 담긴 refresh, access 토큰 모두 삭제처리
        response.setHeader("Authorization", "");
        response.setHeader("X-RefreshToken", "");
        response.setStatus(HttpServletResponse.SC_OK);

        // 응답 body 설정
        String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s",
                            "data":%s
                        }
                        """, ResponseUtils.S0001, ResponseUtils.S0001_MSG, null);

        response.getWriter().write(responseBody);
    }

    /**
     * @Method	- existsByRefresh
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- redis에 refresh 토큰 확인
     * @param refreshToken refresh 토큰
     * @Return	- Boolean 토큰 유: true, 토큰 무: false
     */
    private Boolean existsByRefresh(String refreshToken) {
        RefreshToken token = redisUtil.getRefreshTokenData(refreshToken);
        return !token.getRefresh().isEmpty() ? true : false;
    }

    /**
     * @Method	- deleteByRefresh
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- redis에 있는 refresh 토큰 삭제
     * @param refreshToken refresh 토큰 값
     * @Return	- Boolean 삭제 성공: true, 삭제 실패: false
     */
    private Boolean deleteByRefresh(String refreshToken) {
        return redisUtil.deleteRefreshTokenData(refreshToken) ? true : false;
    }


}
