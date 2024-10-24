package org.daeng2go.daeng2go_server.jwt.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.adminmanagers.mapper.AdminManagersMapper;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.daeng2go.daeng2go_server.members.mapper.MembersMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 업 무 : UserDetailsServiceImpl 구현체
 * 설 명 : 로그인시 DB에 있는 데이터와 비교함 Spring Security에서 자동적으로 사용중
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-04   		최초작성
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    private final MembersMapper membersMapper;
    private final AdminManagersMapper adminManagersMapper;

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {

        // 관리자 로그인 같은 경우 아이디 앞에 adminLogin이 붙어서옴
        String checkAdminLogin = id.substring(0, 10);

        String loginId  = id;
        AdminManagers adminManagers = new AdminManagers();

        Members members = new Members();

        // 관리자인 경우
        if(checkAdminLogin.equals("adminLogin")){
            
            // 관리자 계정은 앞에 adminLogin: 붙어서 오기때문에 제거 후 넣어줘야함
            loginId = id.substring(11);

            // 관리자 계정 넣기
            adminManagers.setId(loginId);

            AdminManagers adminManager = adminManagersMapper.getAdminManagerAllInfo(adminManagers);

            if (adminManager == null) throw new UsernameNotFoundException("관리자 로그인 실패 " + loginId);

            return new UserDetailsImpl(null, adminManager);

        }
        
        // 일반 유저인 경우
        members.setId(loginId);

        Members member = membersMapper.getMember(members);

        if (member == null) throw new UsernameNotFoundException("로그인 실패 " + loginId);

        return new UserDetailsImpl(member, null);

    }


}
