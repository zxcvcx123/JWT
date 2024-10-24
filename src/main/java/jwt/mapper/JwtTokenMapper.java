package org.daeng2go.daeng2go_server.jwt.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.jwt.domain.RefreshToken;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.daeng2go.daeng2go_server.members.dto.MembersDTO;
import org.springframework.transaction.annotation.Transactional;

/**
 * 업 무 : JwtTokenMapper 인터페이스
 * 설 명 : JwtToken DB와 연동할 함수들
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@Mapper
public interface JwtTokenMapper {

    /**
     * @Method	- updateLoginDate
     * @Date	- 2024.06.19
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 날짜 업데이트
     * @param members
     * @Return	- void
     */
    void updateLoginDate(Members members);

    /**
     * @Method	- getMemberOnlyInfo
     * @Date	- 2024.06.19
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- Idx 값으로 회원전체 정보 가져오기
     * @param members
     * @Return	- Members
     */
    Members getMemberOnlyInfo(Members members);


    /**
     * @Method	- setAutoLoginYn
     * @Date	- 2024.07.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 시도 시 자동로그인 Y N 여부 저장
     * @param members
     * @Return	- void 
     */
    void setAutoLoginYn(Members members);

    /**
     * @Method	- getPasswordModifyDate
     * @Date	- 2024.07.10
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 패스워드 수정일 가져오기
     * @param members
     * @Return	- Members
     */
    Members getPasswordModifyDate(Members members);

    /**
     * @Method	- getAdminManagerOnlyInfo
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- Idx 값으로 관리자회원 전체 정보 가져오기
     * @param adminManagers
     * @Return	- AdminManagers
     */
    AdminManagers getAdminManagerOnlyInfo(AdminManagers adminManagers);

    /**
     * @Method	- updateAdminLoginDate
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 로그인 날짜 업데이트
     * @param adminManagers
     * @Return	- void
     */
    void updateAdminLoginDate(AdminManagers adminManagers);

    /**
     * @Method	- getAdminManagerPasswordModifyDate
     * @Date	- 2024.07.29
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- 관리자 계정 패스워드 수정일 가져오기
     * @param adminManagers
     * @Return	- AdminManagers
     */
    AdminManagers getAdminManagerPasswordModifyDate(AdminManagers adminManagers);

}
