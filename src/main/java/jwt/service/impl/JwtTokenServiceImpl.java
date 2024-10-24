package org.daeng2go.daeng2go_server.jwt.service.impl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.common.config.JwtPropertiesConfig;
import org.daeng2go.daeng2go_server.common.exception.MessageException;
import org.daeng2go.daeng2go_server.common.util.redis.RedisUtil;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.jwt.JwtTokenFactory;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.daeng2go.daeng2go_server.jwt.dto.TokenDTO;
import org.daeng2go.daeng2go_server.jwt.mapper.JwtTokenMapper;
import org.daeng2go.daeng2go_server.jwt.service.JwtTokenService;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.daeng2go.daeng2go_server.members.dto.MembersDTO;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 업 무 : JwtTokenServiceImpl 클래스
 * 설 명 : refresh 토큰 재발급 관련 클래스 들
 * <p>
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@Slf4j
@RequiredArgsConstructor
@Service
@Transactional
public class JwtTokenServiceImpl implements JwtTokenService {

    private final JwtTokenFactory jwtTokenFactory;

    private final JwtTokenMapper jwtTokenMapper;

    private final JwtPropertiesConfig jwtPropertiesConfig;

    private final RedisUtil redisUtil;


    /**
     * @param request request 요청
     * @Method    - checkToken
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - refresh 토큰 재발급 요청시 유효성 검증 및 재발급 하는 메소드
     * @Return    - Map<String, String>
     */
    @Override
    public TokenDTO checkToken(HttpServletRequest request) {

        String refreshToken = null;
        //String accessToken = null;

        // 헤더에서 토큰정보 가져오기
        String getAccessToken = request.getHeader("Authorization");
        refreshToken = request.getHeader("X-RefreshToken");

        log.info(" ========== 재발급에 들어온 엑세스 토큰: " + getAccessToken);
        log.info(" ========== 재발급에 들어온 리프레시 토큰: " + refreshToken);

        // 토큰 유무 확인
        if (refreshToken == null || getAccessToken == null) {
            throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0008,ResponseUtils.U0008_MSG, "401"));
        }

        // Bearer 에서 토큰 정보만 추출
        // accessToken = getAccessToken.split(" ")[1];

        // refresh 토큰 expired(만료) 체크
        jwtTokenFactory.isExpired(refreshToken);

        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        String type = jwtTokenFactory.getType(refreshToken);

        if (!type.equals("refresh")) {
            throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0007,ResponseUtils.U0007_MSG, "401"));
        }

        // 토큰 유저 정보 가져오기
        String idx = jwtTokenFactory.getIdx(refreshToken);
        String id = jwtTokenFactory.getId(refreshToken);
        String name = jwtTokenFactory.getName(refreshToken);
        String role = jwtTokenFactory.getRole(refreshToken);

        // access, refresh 토큰 새로 발급하기 (refresh 토큰은 최초 발급된 유효시간을 유지해야해서 oldRefreshTokenTime 을 넣는다)
        String newAccessToken = jwtTokenFactory.createAccessToken("access", idx, id, name, role, jwtPropertiesConfig.getAccessTokenTimer());
        String newRefreshToken = jwtTokenFactory.createRefreshToken("refresh", idx, id, name, role, jwtPropertiesConfig.getRefreshDefaultTokenTimer());

        TokenDTO newToken = new TokenDTO();
        newToken.setAccessToken(newAccessToken);
        newToken.setRefreshToken(newRefreshToken);

        log.info(" ========== ID: " +  id + " | 토큰 재발급 완료 | 엑세스 토큰: " + newAccessToken + " | 리프레시 토큰: " + newRefreshToken +" ========== ");

        return newToken;
    }

    /**
     * @param request request 요청
     * @Method    - checkAdminToken
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - refresh 토큰 재발급 요청시 유효성 검증 및 재발급 하는 메소드
     * @Return    - Map<String, String>
     */
    @Override
    public TokenDTO checkAdminToken(HttpServletRequest request) {

        String refreshToken = null;
        String accessToken = null;

        // 헤더에서 토큰정보 가져오기
        String getAccessToken = request.getHeader("Authorization");
        refreshToken = request.getHeader("X-RefreshToken");

        // 토큰 유무 확인
        if (refreshToken == null || getAccessToken == null) {
            log.error(" =========== 토큰이 확인 되지 않습니다. | refresh: "+ refreshToken +" | accessToken: " + getAccessToken + " =========== ");
            throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0008,ResponseUtils.U0008_MSG, "401"));
        }

        // Bearer 에서 토큰 정보만 추출
        // accessToken = getAccessToken.split(" ")[1];

        // refresh 토큰 expired(만료) 체크
        jwtTokenFactory.isExpired(refreshToken);

        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        String type = jwtTokenFactory.getType(refreshToken);

        if (!type.equals("refresh")) {
            log.error(" ========== 토큰 타입이 리프레시 토큰이 아닙니다. ========== ");
            throw new MessageException(ResponseUtils.responseData(ResponseUtils.U0007,ResponseUtils.U0007_MSG, "401"));
        }

        // 토큰 유저 정보 가져오기
        String idx = jwtTokenFactory.getIdx(refreshToken);
        String id = jwtTokenFactory.getId(refreshToken);
        String name = jwtTokenFactory.getName(refreshToken);
        String role = jwtTokenFactory.getRole(refreshToken);

        // access, refresh 토큰 새로 발급하기 (refresh 토큰은 최초 발급된 유효시간을 유지해야해서 oldRefreshTokenTime 을 넣는다)
        String newAccessToken = jwtTokenFactory.createAccessToken("access", idx, id, name, role, jwtPropertiesConfig.getAccessTokenTimer());
        String newRefreshToken = jwtTokenFactory.createRefreshToken("refresh", idx, id, name, role, jwtPropertiesConfig.getRefreshDefaultTokenTimer());

        TokenDTO newToken = new TokenDTO();
        newToken.setAccessToken(newAccessToken);
        newToken.setRefreshToken(newRefreshToken);

        log.info(" ========== 관리자 ID: " +  id + " | 토큰 재발급 완료 ========== ");

        return newToken;
    }


    /**
     * @param idx memberIdx
     * @Method    - updateLoginDate
     * @Date    - 2024.06.19
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 날짜 업데이트
     * @Return    - void
     */
    @Override
    public void updateLoginDate(String idx) {
        Members members = new Members();
        members.setMemberIdx(Integer.valueOf(idx));
        jwtTokenMapper.updateLoginDate(members);
    }

    /**
     * @param memberIdx
     * @Method    - getMemberOnlyInfo
     * @Date    - 2024.06.19
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - Idx 값으로 회원전체 정보 가져오기
     * @Return    - membersDTO
     */
    @Override
    public Members getMemberOnlyInfo(String memberIdx) {
        Members members = new Members();
        members.setMemberIdx(Integer.valueOf(memberIdx));
        return jwtTokenMapper.getMemberOnlyInfo(members);
    }


    /**
     * @param membersDTO
     * @Method    - setAutoLoginYn
     * @Date    - 2024.07.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 시도 시 자동로그인 Y N 여부
     * @Return    - void
     */
    @Override
    public void setAutoLoginYn(MembersDTO membersDTO) {
        Members members = new Members();
        members.setId(membersDTO.getId());
        members.setAutoLoginYn(membersDTO.getAutoLoginYn());
        jwtTokenMapper.setAutoLoginYn(members);
    }

    /**
     * @param memberIdx 유저 Idx
     * @Method    - getPasswordModifyDate
     * @Date    - 2024.07.10
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 패스워드 수정일 가져오기
     * @Return    - Members
     */
    @Override
    public Members getPasswordModifyDate(String memberIdx) {
        Members member = new Members();
        member.setMemberIdx(Integer.valueOf(memberIdx));
        return jwtTokenMapper.getPasswordModifyDate(member);
    }

    /**
     * @param adminManagerIdx
     * @Method    - updateAdminLoginDate
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 로그인 날짜 업데이트
     * @Return    - void
     */
    @Override
    public void updateAdminLoginDate(String adminManagerIdx) {
        AdminManagers adminManagers = new AdminManagers();
        adminManagers.setAdminManagerIdx(Integer.valueOf(adminManagerIdx));
        jwtTokenMapper.updateAdminLoginDate(adminManagers);
    }

    /**
     * @param adminManagerIdx 관리자 계정 Idx
     * @Method    - getAdminManagerPasswordModifyDate
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - 관리자 계정 패스워드 수정일 가져오기
     * @Return    - AdminManagers
     */
    @Override
    public AdminManagers getAdminManagerPasswordModifyDate(String adminManagerIdx) {

        AdminManagers adminManagers = new AdminManagers();

        adminManagers.setAdminManagerIdx(Integer.valueOf(adminManagerIdx));

        return jwtTokenMapper.getAdminManagerPasswordModifyDate(adminManagers);
    }

    /**
     * @param adminManagerIdx
     * @Method    - getAdminManagerOnlyInfo
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - Idx 값으로 관리자계정 전체 정보 가져오기
     * @Return    - AdminManagers
     */
    @Override
    public AdminManagers getAdminManagerOnlyInfo(String adminManagerIdx) {
        AdminManagers adminManagers = new AdminManagers();
        adminManagers.setAdminManagerIdx(Integer.valueOf(adminManagerIdx));

        return jwtTokenMapper.getAdminManagerOnlyInfo(adminManagers);
    }

    /**
     * @param refreshToken refresh 토큰
     * @Method    - existsByAdminRefresh
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 refresh 토큰 확인
     * @Return    - Boolean 토큰 유: true, 토큰 무: false
     */
    private Boolean existsByAdminRefresh(String refreshToken) {
        RefreshToken token = redisUtil.getAdminRefreshTokenData(refreshToken);
        return !token.getRefresh().isEmpty() ? true : false;

    }

    /**
     * @param refreshToken refresh 토큰 값
     * @Method    - deleteByAdminRefresh
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 있는 refresh 토큰 삭제
     * @Return    - Boolean 삭제 성공: true, 삭제 실패: false
     */
    private Boolean deleteByAdminRefresh(String refreshToken) {
        return redisUtil.deleteAdminRefreshTokenData(refreshToken) ? true : false;

    }


    /**
     * @param id             유저 아이디
     * @param token          refresh 토큰
     * @param expiredSeconds 만료시간 (단위:초)
     * @Method    - addAdminRefreshToken
     * @Date    - 2024.07.29
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 refresh 토큰 저장
     * @Return    - void
     */
    private void addAdminRefreshToken(String idx, String name, String id, String token, String expiredSeconds) {

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
     * @param id             유저 아이디
     * @param token          refresh 토큰
     * @param expiredSeconds 만료시간 (단위:초)
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
     * @param refreshToken refresh 토큰 값
     * @Method    - deleteByRefresh
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 있는 refresh 토큰 삭제
     * @Return    - Boolean 삭제 성공: true, 삭제 실패: false
     */
    private Boolean deleteByRefresh(String refreshToken) {
        return redisUtil.deleteRefreshTokenData(refreshToken) ? true : false;
    }

    /**
     * @param refreshToken refresh 토큰
     * @Method    - existsByRefresh
     * @Date    - 2024.06.03
     * @Writter    - 정정모
     * @EditHistory    -
     * @Discript    - redis에 refresh 토큰 확인
     * @Return    - Boolean 토큰 유: true, 토큰 무: false
     */
    private Boolean existsByRefresh(String refreshToken) {
        RefreshToken token = redisUtil.getRefreshTokenData(refreshToken);
        return !token.getRefresh().isEmpty() ? true : false;
    }
}
