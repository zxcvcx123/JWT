package org.daeng2go.daeng2go_server.jwt.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.adminmanagers.dto.AdminManagersDTO;
import org.daeng2go.daeng2go_server.common.config.JwtPropertiesConfig;
import org.daeng2go.daeng2go_server.common.util.date.CommonDateUtil;
import org.daeng2go.daeng2go_server.common.util.ratelimit.RateLimiterUtil;
import org.daeng2go.daeng2go_server.common.util.redis.RedisUtil;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.jwt.JwtTokenFactory;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.daeng2go.daeng2go_server.jwt.service.JwtTokenService;
import org.daeng2go.daeng2go_server.jwt.service.impl.CustomAuthenticationProvider;
import org.daeng2go.daeng2go_server.jwt.service.impl.UserDetailsImpl;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;


/**
 * 업 무 : 로그인 필터
 * 설 명 : 로그인 담당 / 로그인 성공, 실패시 처리 등등...
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-04   		최초작성
 */
@Slf4j
public class AdminLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtTokenFactory jwtTokenFactory;

    private final JwtTokenService jwtTokenService;

    private final JwtPropertiesConfig jwtProperties;

    private final RedisUtil redisUtil;

    private final RateLimiterUtil rateLimiterUtil;

    // @RequiredArgsConstructor 말고 직접 생성자 만들어서 주입 후 마지막에 login path 경로 설정
    public AdminLoginFilter(AuthenticationManager authenticationManager,
                            JwtTokenFactory jwtTokenFactory,
                            JwtTokenService jwtTokenService,
                            JwtPropertiesConfig jwtProperties,
                            RedisUtil redisUtil,
                            RateLimiterUtil rateLimiterUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenFactory = jwtTokenFactory;
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
        this.redisUtil = redisUtil;
        this.rateLimiterUtil = rateLimiterUtil;
        // login 요청 path 설정
        setFilterProcessesUrl("/admin/token/login");
    }

    /**
     * @Method	- attemptAuthentication
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 요청시 들어 온 정보를 Authentication 객체에 담아 시큐리티필터로 이관
     * @param request request 요청
     * @param response response 응답
     * @Return	- Authentication
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // 어드민 로그인으로 들어올시 null 로 줘서 successfulAuthentication에서 처리

            /* 필요한 객체 생성 */
            ObjectMapper objectMapper = new ObjectMapper();
            AdminManagersDTO adminManagersDTO = new AdminManagersDTO();

            /* 테이블 정보에 맞게 세팅 하는 작업 */
            setUsernameParameter("id");
            setPasswordParameter("password");


            /* HttpServletRquest로 받은 body 데이터를 DTO에 맞게 변환 */
            try {

                ServletInputStream inputStream = request.getInputStream();
                String body = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
                adminManagersDTO = objectMapper.readValue(body, AdminManagersDTO.class);

            } catch (IOException e) {

                log.warn(" ========== LoginFilter attemptAuthentication 메소드 문제 발생! ==========");
                throw new RuntimeException(e);

            }

            /* 클라이언트 요청에서 id, password, autoLoginYn */
            String id =  "adminLogin:"+adminManagersDTO.getId();
            String password =  adminManagersDTO.getPassword();

            adminManagersDTO.setId(id);
            adminManagersDTO.setPassword(password);

            /* 스프링 시큐리티에서 id, password를 검증하기 위해서는 token에 담아야 함 */
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(adminManagersDTO, password, null);

            /* token에 담은 검증을 위한 AuthenticationManager로 전달 */
            // 로그인 검증 과정: authenticationManager는 AuthenticationProvider 로 전달
            // AuthenticationProvider 기능중 DaoAuthenticationProvider 활용해 DB에 저장된 암호화 패스워드를 검증해서 id, password가 일치하는지 확인
            return authenticationManager.authenticate(authToken);


    }

    /**
     * @Method	- successfulAuthentication
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
     * @param request request 요청
     * @param response response 응답
     * @param chain
     * @param authentication
     * @Return	- void
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // 유저정보
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Idx, 아이디, 이름
        String idx = userDetails.getUserIdx();
        String id = userDetails.getUserId();
        String name = userDetails.getUsername();

        // 탈퇴 계정인지 확인
        AdminManagers adminManagers = jwtTokenService.getAdminManagerOnlyInfo(idx);

        // 탈퇴 계정 유무 확인 Y: 탈퇴 / N: 회원유지
        String checkDelYn = adminManagers.getDelYn();

        // 탈퇴 계정에 맞게 응답 후 메소드 종료 (토큰 발급 x)
        if(checkDelYn.equals("Y")){
            // 응답 값 설정
            response.setStatus(HttpStatus.OK.value());

            // 응답의 콘텐츠 유형 및 문자 인코딩 설정
            response.setContentType("application/json; charset=UTF-8");
            response.setCharacterEncoding("UTF-8");

            // 탈퇴처리된 계정 로그인시 응답 값 설정
            String responseBody = String.format("""
                        {
                            "code":"%s",
                            "msg":"%s",
                            "data":%s
                        }
                        """, ResponseUtils.U0009, ResponseUtils.U0009_MSG, null);


            // 응답 본문 설정
            response.getWriter().write(responseBody);
            return;
        }

        // 권한 정보
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends  GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String access = "";
        String refresh = "";

        // 리프레쉬 토큰 발급 (1일)
        // 토큰 생성
        access = jwtTokenFactory.createAccessToken("access", idx, id, name, role, jwtProperties.getAccessTokenTimer());
        refresh = jwtTokenFactory.createRefreshToken("refresh", idx, id, name, role, jwtProperties.getRefreshDefaultTokenTimer());

        // 로그인 시간 업데이트
        jwtTokenService.updateAdminLoginDate(idx);
        rateLimiterUtil.resolveBucket(idx);

        log.info(" ========== " + id + " 님 로그인 (토큰 발급) 성공 | 엑세스 토큰: " + access + " | 리프레시 토큰: " + refresh + " ========== ");

        response.setStatus(HttpStatus.OK.value());

        // 응답의 콘텐츠 유형 및 문자 인코딩 설정
        response.setContentType("application/json; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        // 비밀번호 변경일 3개월 확인 0: 오류, 1: 3개월 이내, 2: 3개월 지남
        Integer checkPasswordDate = checkMonthPasswordDate(idx);

        // 비밀번호 변경일 3개월 이후 로그인 유저
        if(checkPasswordDate == 2) {
            // 응답 값 설정
            String responseBody = String.format("""
                    {
                        "code":"%s",
                        "msg":"%s",
                        "data":{
                            "accessToken": "%s",
                            "refreshToken": "%s"
                            }
                    }
                    """, ResponseUtils.S0003, ResponseUtils.S0003_MSG, access, refresh);

            // 응답 본문 설정
            response.getWriter().write(responseBody);

            log.info(" ========== " + id + " 님 로그인 성공 | 비밀번호 변경 대상자 입니다. ========== ");

            return;
        }

        // 비밀번호 변경일 3개월 이내 로그인 유저
        if(checkPasswordDate == 1) {
            // 응답 값 설정
            String responseBody = String.format("""
                    {
                        "code":"%s",
                        "msg":"%s",
                        "data":{
                            "accessToken": "%s",
                            "refreshToken": "%s"
                            }
                    }
                    """, ResponseUtils.S0002, ResponseUtils.S0002_MSG, access, refresh);

            // 응답 본문 설정
            response.getWriter().write(responseBody);

            log.info(" ========== " + id + " 님 로그인 성공 ========== ");
        }

        // 오류
        if(checkPasswordDate == 0) {
            // 응답 값 설정
            String responseBody = String.format("""
                    {
                        "code":"%s",
                        "msg":"%s",
                        "data":{
                            "accessToken": "%s",
                            "refreshToken": "%s"
                            }
                    }
                    """, ResponseUtils.E0002, ResponseUtils.E0002_MSG, access, refresh);

            // 응답 본문 설정
            response.getWriter().write(responseBody);

            log.info(" ========== " + id + " 님 로그인 실패 했습니다 | LoginFilter를 확인해주세요. ========== ");

            return;
        }

    }

    /**
     * @Method	- unsuccessfulAuthentication
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 실패시 실행하는 메소드
     * @param request request 요청
     * @param response response 응답
     * @param failed 실패 관련 Exception
     * @Return	- void
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {

        response.setStatus(200);

        // 응답의 콘텐츠 유형 및 문자 인코딩 설정
        response.setContentType("application/json; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        if (failed.getMessage().equals("N01")) {
            // 응답 body 설정
            String responseBody = String.format("""
                    {
                        "code":"%s",
                        "msg":"%s",
                        "data":%s
                    }
                    """, ResponseUtils.U0014, "가입되어 있지 않은 계정입니다.", 1);

            response.getWriter().write(responseBody);

            return;
        }

        if (failed.getMessage().equals("P01")) {
            // 응답 body 설정
            String responseBody = String.format("""
                    {
                        "code":"%s",
                        "msg":"%s",
                        "data":%s
                    }
                    """, ResponseUtils.U0014, "입력한 비밀번호가 다릅니다.", 2);

            response.getWriter().write(responseBody);

        }
    }

    /**
     * @Method	- setUsernameParameter
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 테이블에 정의된 id / password 컬럼 값을 맞추기 위해 사용
     * @param usernameParameter 지정할 파라미터명 (유저 ID 컬럼명)
     * @Return	- void
     */
    @Override
    public void setUsernameParameter(String usernameParameter) {
        super.setUsernameParameter(usernameParameter);
    }

    /**
     * @Method	- addRefreshToken
     * @Date	- 2024.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- redis에 refresh 토큰 저장
     * @param id 유저 아이디
     * @param token refresh 토큰 값
     * @param expiredSeconds 만료 시간 설정 (단위:초)
     * @Return	- void
     */
    private void addRefreshToken(String idx, String name, String id, String token, String expiredSeconds) {

        RefreshToken refreshToken = new RefreshToken();

        // 초로 변환
        Long expiredSetSeconds = Long.parseLong(expiredSeconds);

        refreshToken.setIdx(idx);
        refreshToken.setName(name);
        refreshToken.setId(id);
        refreshToken.setRefresh(token);
        refreshToken.setIssuedAt(new Date(System.currentTimeMillis()));
        refreshToken.setExpiration(new Date(System.currentTimeMillis() + expiredSetSeconds * 1000L));

        Long setTime = expiredSetSeconds;

        redisUtil.setAdminRefreshTokenExpire(refreshToken, setTime);
    }

    /**
     * @Method	- checkMonthPasswordDate
     * @Date	- 2024.07.10
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 비밀번호 수정일 3개월 체크
     * @param memberIdx 유저 idx
     * @Return	- Integer 0: 오류, 1: 3개월 이내, 2: 3개월 지남
     */
    private Integer checkMonthPasswordDate(String memberIdx){

        AdminManagers adminManagers = jwtTokenService.getAdminManagerPasswordModifyDate(memberIdx);

        // 오류: 0
        if(adminManagers == null) return 0;


        // DB에서 가져온 비밀번호 변경일
        Timestamp passwordDate = adminManagers.getPasswordDt();

        // 현재 시간
        LocalDateTime now = CommonDateUtil.getDateNow();

        // 비밀번호 변경일 타입 변환
        LocalDateTime passwordDateTime = passwordDate.toLocalDateTime();

        // 계산
        long monthsBetween = ChronoUnit.MONTHS.between(passwordDateTime, now);

        // 3개월 검증
        // 3개월 지남
        if(monthsBetween >= 3) return 2;

        // 3개월 이내
        if(monthsBetween < 3) return 1;

        // 오류: 0
        return 0;

    }

}
