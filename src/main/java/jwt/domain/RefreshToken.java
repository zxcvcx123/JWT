package org.daeng2go.daeng2go_server.jwt.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.ibatis.type.Alias;

import java.util.Date;

/**
 * 업 무 : RefreshToken 클래스
 * 설 명 : RefreshToken 객체
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Alias("RefreshToken")
public class RefreshToken {

    private String idx;

    private String name;

    private String id;

    private String refresh;

    private Date issuedAt;

    private Date expiration;


}
