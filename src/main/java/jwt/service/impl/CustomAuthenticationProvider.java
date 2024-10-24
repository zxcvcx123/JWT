package org.daeng2go.daeng2go_server.jwt.service.impl;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSession;
import org.daeng2go.daeng2go_server.adminbreeds.dto.AdminBreedsDTO;
import org.daeng2go.daeng2go_server.adminmanagers.dto.AdminManagersDTO;
import org.daeng2go.daeng2go_server.adminmembers.dto.AdminMembersDTO;
import org.daeng2go.daeng2go_server.common.exception.MessageException;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.common.util.response.dto.ResponseDTO;
import org.daeng2go.daeng2go_server.jwt.service.JwtTokenService;
import org.daeng2go.daeng2go_server.members.dto.MembersDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 업 무 : CustomAuthenticationProvider 클래스
 * 설 명 : 로그인시 기존 AuthenticationProvider 로는 아이디, 비밀번호 별로 상황별로 분기처리가 안되서 커스텀 만들어서 사용
 * <p>
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-08-20   		최초작성
 */
@Component
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final SqlSession sqlSession;
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    // userDetailService 생성자로 주입해서 아래 authenticate 메소드에서 활용
    // sqlSession 도 같이 생성자로 주입
    public CustomAuthenticationProvider(UserDetailsService userDetailsService, SqlSession sqlSession) {
        this.userDetailsServiceImpl = (UserDetailsServiceImpl) userDetailsService;
        this.sqlSession = sqlSession;
    }

    // SecurityConfig 에 Bean 등록되어 있지만 클래스 구조상 @RequiredArgsConstructor 사용 안돼서
    // 수동으로 만들어서 사용하기
    private PasswordEncoder passwordEncoder() {
        // BCrypt Encoder 사용
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * @param authentication LoginFilter에서 넘겨준 암호화된 유저정보
     * @throws AuthenticationException
     * @Method - authenticate
     * @Date - 2024.08.20
     * @Writter - 정정모
     * @EditHistory -
     * @Discript - 로그인시 검증을 여기서 진행 (아이디 틀린경우, 아이디는 맞는데 비밀번호 틀린경우 각기 다른 분기처리를 위해 커스텀 클래스 생성)
     * @Return - Authentication
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = "";
        String password = "";
        String autoLoginYn = "";

        /* 회원 로그인 */

        if(authentication.getPrincipal() instanceof MembersDTO){
            MembersDTO member = (MembersDTO) authentication.getPrincipal();

            username = member.getId();
            password = authentication.getCredentials().toString();
            autoLoginYn = member.getAutoLoginYn();

            UserDetailsImpl user;

            // 유저 검증
            try {
                user = (UserDetailsImpl) userDetailsServiceImpl.loadUserByUsername(username);
            } catch (Exception e) {
                // 유저가 없는 경우 N01 리턴
                throw new BadCredentialsException("N01");
            }

            // 패스워드 검증
            if (!passwordEncoder().matches(password, user.getPassword())) {
                // 패스워드가 틀린 경우 P01 리턴
                throw new BadCredentialsException("P01");
            }

            // 자동로그인 여부 값 DB에 저장
            Integer result = sqlSession.update("setAutoLoginYn", member);

            if(result != 1){
                log.error(" ========== 로그인 시도시 자동로그인 업데이트 도중 에러발생!!! | CustomAuthenticationProvider 클래스 문제 발생 ========== ");
                throw new MessageException(ResponseUtils.responseData(ResponseUtils.E0001, ResponseUtils.E0001_MSG));
            }

            return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());

        }

        /* 관리자 로그인 */
        if(authentication.getPrincipal() instanceof AdminManagersDTO) {
            log.info(" ========== 관리자 로그인 ========== ");
            AdminManagersDTO adminManagers = (AdminManagersDTO) authentication.getPrincipal();
            username = adminManagers.getId();
            password = authentication.getCredentials().toString();
        }

        UserDetailsImpl user;

        // 유저 검증
        try {
            user = (UserDetailsImpl) userDetailsServiceImpl.loadUserByUsername(username);
        } catch (Exception e) {
            // 유저가 없는 경우 N01 리턴
            throw new BadCredentialsException("N01");
        }

        // 패스워드 검증
        if (!passwordEncoder().matches(password, user.getPassword())) {
            // 패스워드가 틀린 경우 P01 리턴
            throw new BadCredentialsException("P01");
        }

        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
