package org.daeng2go.daeng2go_server.jwt.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.common.config.JwtPropertiesConfig;
import org.daeng2go.daeng2go_server.common.exception.MessageException;
import org.daeng2go.daeng2go_server.common.util.date.CommonDateUtil;
import org.daeng2go.daeng2go_server.common.util.ratelimit.RateLimiterUtil;
import org.daeng2go.daeng2go_server.common.util.redis.RedisUtil;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.jwt.JwtTokenFactory;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.daeng2go.daeng2go_server.jwt.service.JwtTokenService;
import org.daeng2go.daeng2go_server.jwt.service.impl.CustomAuthenticationProvider;
import org.daeng2go.daeng2go_server.jwt.service.impl.UserDetailsImpl;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.daeng2go.daeng2go_server.members.dto.MembersDTO;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 * <p>
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-04   		최초작성
 */
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final CustomAuthenticationProvider customAuthenticationProvider;

    private final JwtTokenFactory jwtTokenFactory;

    private final JwtTokenService jwtTokenService;

    private final JwtPropertiesConfig jwtProperties;

    private final RedisUtil redisUtil;

    private final RateLimiterUtil rateLimiterUtil;

    private final ObjectMapper objectMapper;

    // @RequiredArgsConstructor 말고 직접 생성자 만들어서 주입 후 마지막에 login path 경로 설정
    public LoginFilter(AuthenticationManager authenticationManager,
                       CustomAuthenticationProvider customAuthenticationProvider,
                       JwtTokenFactory jwtTokenFactory,
                       JwtTokenService jwtTokenService,
                       JwtPropertiesConfig jwtProperties,
                       RedisUtil redisUtil,
                       RateLimiterUtil rateLimiterUtil,
                       ObjectMapper objectMapper
    ) {
        this.authenticationManager = authenticationManager;
        this.customAuthenticationProvider = customAuthenticationProvider;
        this.jwtTokenFactory = jwtTokenFactory;
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
        this.redisUtil = redisUtil;
        this.rateLimiterUtil = rateLimiterUtil;
        this.objectMapper = objectMapper;
        // login 요청 path 설정
        setFilterProcessesUrl("/token/login");
    }

    /**
     * @param request  request 요청
     * @param response response 응답
     * @Method    - attemptAuthentication
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 요청시 들어 온 정보를 Authentication 객체에 담아 시큐리티필터로 이관
     * @Return    - Authentication
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        // 어드민 로그인으로 들어올시 null 로 줘서 successfulAuthentication에서 처리
        if (request.getServletPath().equals("/admin/token/login")) return null;

        /* 필요한 객체 생성 */
        //MembersDTO membersDTO = new MembersDTO();

        /* 테이블 정보에 맞게 세팅 하는 작업 */
        setUsernameParameter("id");
        setPasswordParameter("password");

        MembersDTO membersDTO = convertServletBody(request, MembersDTO.class);

        /* 클라이언트 요청에서 id, password, autoLoginYn */
        String id = membersDTO.getId();
        String password = membersDTO.getPassword();

        /* 스프링 시큐리티에서 id, password를 검증하기 위해서는 token에 담아야 함 */
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(membersDTO, password, null);

        /* token에 담은 검증을 위한 AuthenticationManager로 전달 */
        // 로그인 검증 과정: authenticationManager는 AuthenticationProvider 로 전달
        // AuthenticationProvider 기능중 DaoAuthenticationProvider 활용해 DB에 저장된 암호화 패스워드를 검증해서 id, password가 일치하는지 확인
        //return customAuthenticationProvider.authenticate(authToken);
        return customAuthenticationProvider.authenticate(authToken);
    }

    /**
     * @param request        request 요청
     * @param response       response 응답
     * @param chain
     * @param authentication
     * @throws IOException
     * @throws ServletException
     * @Method    - successfulAuthentication
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
     * @Return    - void
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // 관리자 경로로 로그인 요청이 들어온 경우 AdminLoginFilter로 넘김
        if (request.getServletPath().equals("/admin/token/login")) chain.doFilter(request, response);

        // 유저정보
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Idx, 아이디, 이름, 자동저장 유무
        String idx = userDetails.getUserIdx();
        String id = userDetails.getUserId();
        String name = userDetails.getUsername();
        String autoLoginYn = userDetails.getAutoLoginYn();

        // 탈퇴 계정인지 확인
        Members members = jwtTokenService.getMemberOnlyInfo(idx);

        // 응답의 콘텐츠 유형 및 문자 인코딩 설정
        response.setContentType("application/json; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        // 탈퇴 계정이면 null 맞게 응답 후 메소드 종료 (토큰 발급 x)
        if (members == null) {

            // 응답 값 설정
            response.setStatus(HttpStatus.OK.value());

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
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String access = "";
        String refresh = "";

        // 자동로그인 Y 리프레쉬 토큰 발급 (7일)
        if (autoLoginYn.equals("Y")) {
            // 토큰 생성
            access = jwtTokenFactory.createAccessToken("access", idx, id, name, role, jwtProperties.getAccessTokenTimer());
            refresh = jwtTokenFactory.createRefreshToken("refresh", idx, id, name, role, jwtProperties.getRefreshAutoTokenTimer());
        }

        // 자동로그인 N 리프레쉬 토큰 발급 (1일)
        if (autoLoginYn.equals("N")) {
            // 토큰 생성
            access = jwtTokenFactory.createAccessToken("access", idx, id, name, role, jwtProperties.getAccessTokenTimer());
            refresh = jwtTokenFactory.createRefreshToken("refresh", idx, id, name, role, jwtProperties.getRefreshDefaultTokenTimer());
        }

        // 로그인 시간 업데이트
        jwtTokenService.updateLoginDate(idx);
        rateLimiterUtil.resolveBucket(idx);

        log.info(" ========== " + id + " 님 로그인 (토큰 발급) 성공 | 엑세스 토큰: " + access + " | 리프레시 토큰: " + refresh + " ========== ");

        response.setStatus(HttpStatus.OK.value());

        // 비밀번호 변경일 3개월 확인 0: 오류, 1: 3개월 이내, 2: 3개월 지남
        Integer checkPasswordDate = checkMonthPasswordDate(idx);

        // 비밀번호 변경일 3개월 이후 로그인 유저
        if (checkPasswordDate == 2) {
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
        if (checkPasswordDate == 1) {
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

            return;
        }

        // 오류
        if (checkPasswordDate == 0) {
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

        }

    }

    /**
     * @param request  request 요청
     * @param response response 응답
     * @param failed   실패 관련 Exception
     * @Method    - unsuccessfulAuthentication
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 실패시 실행하는 메소드
     * @Return    - void
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
                    """, ResponseUtils.U0014, "가입되어 있지 않은 이메일입니다.", 1);

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
     * @param usernameParameter 지정할 파라미터명 (유저 ID 컬럼명)
     * @Method    - setUsernameParameter
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 테이블에 정의된 id / password 컬럼 값을 맞추기 위해 사용
     * @Return    - void
     */
    @Override
    public void setUsernameParameter(String usernameParameter) {
        super.setUsernameParameter(usernameParameter);
    }

    /**
     * @param id             유저 아이디
     * @param token          refresh 토큰 값
     * @param expiredSeconds 만료 시간 설정 (단위:초)
     * @Method    - addRefreshToken
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 refresh 토큰 저장
     * @Return    - void
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

        redisUtil.setRefreshTokenExpire(refreshToken, setTime);
    }

    /**
     * @param memberIdx 유저 idx
     * @Method    - checkMonthPasswordDate
     * @Date    - 2024.07.10
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 비밀번호 수정일 3개월 체크
     * @Return    - Integer 0: 오류, 1: 3개월 이내, 2: 3개월 지남
     */
    private Integer checkMonthPasswordDate(String memberIdx) {

        Members member = jwtTokenService.getPasswordModifyDate(memberIdx);

        // 오류: 0
        if (member == null) return 0;

        // DB에서 가져온 비밀번호 변경일
        Timestamp passwordDate = member.getPasswordDt();

        // 현재 시간
        LocalDateTime now = CommonDateUtil.getDateNow();

        // 비밀번호 변경일 타입 변환
        LocalDateTime passwordDateTime = passwordDate.toLocalDateTime();

        // 계산
        long monthsBetween = ChronoUnit.MONTHS.between(passwordDateTime, now);

        // 3개월 검증
        // 3개월 지남
        if (monthsBetween >= 3) return 2;

        // 3개월 이내
        if (monthsBetween < 3) return 1;

        // 오류: 0
        return 0;

    }

    /**
     * @param request 서블릿 request
     * @param returnObj 리턴할 객체
     * @Method    - convertServletBody
     * @Date    - 2024.08.22
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - HttpServletRequest의 Body 값을 객체로 변환
     * @Return    - T 리턴할 객체
     */
    private <T> T convertServletBody(HttpServletRequest request, Class<T> returnObj){

        /* HttpServletRquest로 받은 body 데이터를 DTO에 맞게 변환 */
        try {

            ServletInputStream inputStream = request.getInputStream();
            String body = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);

            if(body == null || body.isBlank()){
                throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0001, ResponseUtils.U0001_MSG));
            }

            T data = objectMapper.readValue(body, returnObj);
            return data;
        } catch (IOException e) {
            log.warn(" ========== HttpServletRequest -> Body 값 변경 메소드 문제 발생! | convertServletBody() ==========");
            throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0001, ResponseUtils.U0001_MSG));
        }

    }

}
