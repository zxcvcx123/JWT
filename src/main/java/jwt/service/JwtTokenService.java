package org.daeng2go.daeng2go_server.jwt.service;

import jakarta.servlet.http.HttpServletRequest;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.daeng2go.daeng2go_server.jwt.dto.TokenDTO;
import org.daeng2go.daeng2go_server.jwt.service.impl.UserDetailsImpl;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.daeng2go.daeng2go_server.members.dto.MembersDTO;

import java.util.Map;
import java.util.Objects;

/**
 * 업 무 : JwtTokenService 인터페이스
 * 설 명 : Jwt 관련
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
public interface JwtTokenService {

    /**
     * @Method	- reissueToken
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- access, refresh 토큰 재발급
     * @param request HttpRequest 오는 데이터들
     * @Return	- Map<String, String>
     */
    TokenDTO checkToken(HttpServletRequest request);

    /**
     * @Method	- updateLoginDate
     * @Date	- 2024.06.19
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 날짜 업데이트
     * @param memberIdx
     * @Return	- void
     */
    void updateLoginDate(String memberIdx);

    /**
     * @Method	- getMemberOnlyInfo
     * @Date	- 2024.06.19
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- Idx 값으로 회원전체 정보 가져오기
     * @param memberIdx
     * @Return	- Members
     */
    Members getMemberOnlyInfo(String memberIdx);

    /**
     * @Method	- setAutoLoginYn
     * @Date	- 2024.07.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 시도 시 자동로그인 Y N 여부
     * @param membersDTO
     * @Return	- void
     */
    void setAutoLoginYn(MembersDTO membersDTO);

    /**
     * @Method	- getPasswordModifyDate
     * @Date	- 2024.07.10
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 패스워드 수정일 가져오기
     * @param memberIdx 유저 Idx
     * @Return	- Members
     */
    Members getPasswordModifyDate(String memberIdx);


    /**
     * @Method	- checkAdminToken
     * @Date	- 24.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- access, refresh 토큰 재발급
     * @param request HttpRequest 오는 데이터들
     * @Return	- Map<String, String>
     */
    TokenDTO checkAdminToken(HttpServletRequest request);

    /**
     * @Method	- updateAdminLoginDate
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 날짜 업데이트
     * @param adminManagerIdx
     * @Return	- void
     */
    void updateAdminLoginDate(String adminManagerIdx);

    /**
     * @Method	- getAdminManagerOnlyInfo
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- Idx 값으로 관리자계정 전체 정보 가져오기
     * @param adminManagerIdx
     * @Return	- AdminManagers
     */
    AdminManagers getAdminManagerOnlyInfo(String adminManagerIdx);

    /**
     * @Method	- getAdminManagerPasswordModifyDate
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	-  관리자 계정 패스워드 수정일 가져오기
     * @param adminManagerIdx 관리자 계정 Idx
     * @Return	- AdminManagers
     */
    AdminManagers getAdminManagerPasswordModifyDate(String adminManagerIdx);


}
