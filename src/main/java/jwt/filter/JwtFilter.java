package org.daeng2go.daeng2go_server.jwt.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.jwt.JwtTokenFactory;
import org.daeng2go.daeng2go_server.jwt.service.impl.UserDetailsImpl;
import org.daeng2go.daeng2go_server.jwt.util.JwtFreePath;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;


/**
 * 업 무 : JwtFilter
 * 설 명 : Jwt 검증을 담당하는 부분 / 토큰 유무, 유효시간 확인, 권한 확인
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtTokenFactory jwtTokenFactory;


    /**
     * @Method	- doFilterInternal
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- Jwt 검증 후 시큐리티 쪽으로 넘겨주기
     * @param request HttpRequest 객체
     * @param response HttpResponse 객체
     * @param filterChain filterChain 객체 (이걸 통해 다음 동작할 필터에게 넘겨줄 수 있음)
     * @Return	- void
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 엑세스 토큰 가져오기
        String accessToken = null;
        accessToken = request.getHeader("Authorization");

        // path 에 따라 다르게 처리
        String requestPath = request.getServletPath();

        // 토큰이 필요 없는 경로는 jwtFilter 과정 생략 되게 설정
        if(checkPath(requestPath, request)){
            // 다음 필터로 넘겨주기
            filterChain.doFilter(request, response);
            return;
        }

        response.setContentType("application/json; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");


        // Authorization 헤더 검증, 토큰 유무 확인
        if(accessToken == null || !accessToken.startsWith("Bearer ")){

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0008, ResponseUtils.U0008_MSG, null);

            log.error(" ========== 필터에서 엑세스 토큰 확인 못함 ========== ");
            response.getWriter().write(responseBody);

            return;

        }

        // Bearer 에서 토큰 정보만 추출
        String token = accessToken.split(" ")[1];

        log.info(" ========== 필터에 들어온 엑세스 토큰: " + token);

        // 엑세스 토큰 유효시간 확인
        try {
            jwtTokenFactory.isExpired(token);
        } catch (SignatureException se){

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0002, "토큰 위조를 감지했습니다. 추적 시작", null);

            log.error(" ========== 토큰 위조 감지!!! ========== ");
            response.getWriter().write(responseBody);
            return;

        } catch (ExpiredJwtException e){

            // 응답의 콘텐츠 유형 및 문자 인코딩 설정
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0006, ResponseUtils.U0006_MSG, null);

            log.error(" ========== 필터에서 만료된 엑세스 토큰 확인 ========== ");
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
            log.error(" ========== 필터에서 올바르지 못한 토큰 형식 확인 ========== ");
            response.getWriter().write(responseBody);

            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String type = jwtTokenFactory.getType(token);
    
        // access 토큰이 아닌 경우
        if(!type.equals("access")){

            // 응답의 콘텐츠 유형 및 문자 인코딩 설정
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // 응답 body 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s"
                        }
                        """, ResponseUtils.U0007, ResponseUtils.U0007_MSG, null);

            response.getWriter().write(responseBody);
            return;

        }

        // payload 정보 가져오기
        String idx = jwtTokenFactory.getIdx(token);
        String id = jwtTokenFactory.getId(token);
        String name = jwtTokenFactory.getName(token);
        String role = jwtTokenFactory.getRole(token);

        // 토큰을 기반으로 세션을 일시적으로 저장시켜야 해서 사용
        // 이걸 안하면 권한에 따른 기능이나 경로 같은거 사용 못함 (시큐리티가 권한, 경로 확인하니깐)
        Members members = new Members();
        AdminManagers adminManagers = new AdminManagers();

        // admin 경로로 온 경우
        if(request.getServletPath().startsWith("/admin")){
            
            adminManagers.setAdminManagerIdx(Integer.parseInt(idx));
            adminManagers.setId(id);
            adminManagers.setName(name);
            // 암호는 간단하게 해야함 안그러면 DB에 계속 조회해야하는데 비용이 많이 들어서 간단하게 설정
            adminManagers.setPassword("password");

            // UserDetails에 회원정보 넣기
            members = null;
            UserDetailsImpl userDetails = new UserDetailsImpl(members, adminManagers);

            // 스프링 시큐리티 인증 토큰 생성
            Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // 세션에 사용자 등록해서 권한 확인
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // 다음 동작할 필터에게 넘겨줌
            filterChain.doFilter(request, response);

            return;
        }

        // 일반 경로로 온 경우
        if(!request.getServletPath().startsWith("/admin")) {
            members.setMemberIdx(Integer.parseInt(idx));
            members.setId(id);
            members.setName(name);

            // 암호는 간단하게 해야함 안그러면 DB에 계속 조회해야하는데 비용이 많이 들어서 간단하게 설정
            members.setPassword("password");

            // ROLE_ 를 문자열을 이어줘야 스프링 시큐리티에서 hasRole를 제대로 검사함 예)ROLE_ADMIN (O), ADMIN (X)
            members.setRole("ROLE_" + role);

            adminManagers = null;
            // UserDetails에 회원정보 넣기
            UserDetailsImpl userDetails = new UserDetailsImpl(members, adminManagers);

            // 스프링 시큐리티 인증 토큰 생성
            Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // 세션에 사용자 등록해서 권한 확인
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // 다음 동작할 필터에게 넘겨줌
            filterChain.doFilter(request, response);

        }

    }

    /**
     * @Method	- checkPath
     * @Date	- 2024.06.12
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 회원, 비회원에 따른 api 요청 가능 여부
     * @param requestPath 회원이 요청한 api 주소
     * @param request   GET, POST 요청을 확인하기 위해
     * @Return	- boolean
     */
    private boolean checkPath(String requestPath, HttpServletRequest request){

        // 비회원 path 검증 제외해야해서 pathList 가져오기
        List<String> pathList = JwtFreePath.PATH.getFreePath();

        int result = 0;

        // requestPath를 pathList에 있는 값들과 대입 
        for(String path: pathList) {
            // 관리자 계정 생성 Post 요청은 생략
            if (requestPath.startsWith(path)){
                // 비회원이 사용 가능한 path 요청이 온 경우 result 값 추가
                result ++;
            }
        }

        // 비회원 사용 가능한 path에 값이 0보다 크면 통과
        // 회원만 사용 가능한 path면 값이 추가 안되니깐 0
        return  result > 0 ? true : false;

    }

}
