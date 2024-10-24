package org.daeng2go.daeng2go_server.jwt.service.impl;

import org.daeng2go.daeng2go_server.adminmanagers.domain.AdminManagers;
import org.daeng2go.daeng2go_server.members.domain.Members;
import org.springframework.data.relational.core.sql.In;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;


/**
 * 업 무 : UserDetailsImpl 구현체
 * 설 명 : 로그인시 토큰 발급 되면서 같이 SpringContext에 저장되는데 거기에 있는 유저정보를 꺼낼 수 있음
 * <p>
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-04   		최초작성
 */
public class UserDetailsImpl implements UserDetails {

    private final Members members;

    private final AdminManagers adminManagers;

    public UserDetailsImpl(Members members, AdminManagers adminManagers) {
        this.members = members;
        this.adminManagers = adminManagers;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return members == null && adminManagers != null ? adminManagers.getPosition() : members.getRole();
            }
        });
        return collection;
    }

    public String getUserIdx() {
        return members == null && adminManagers != null ? String.valueOf(adminManagers.getAdminManagerIdx()) : String.valueOf(members.getMemberIdx());
    }

    public String getUserId() {
        return members == null && adminManagers != null ? adminManagers.getId() : members.getId();
    }

    public String getAutoLoginYn() {
        return members.getAutoLoginYn();
    }

    @Override
    public String getPassword() {
        return members == null && adminManagers != null ? adminManagers.getPassword() : members.getPassword();
    }

    @Override
    public String getUsername() {
        return members == null && adminManagers != null ? adminManagers.getName() : members.getName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


}
