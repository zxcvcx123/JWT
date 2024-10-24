package org.daeng2go.daeng2go_server.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 업 무 : TokenDTO 클래스
 * 설 명 : TokenDTO 토큰 발급, 재발급 때 리턴해주기 위해
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-07-08   		최초작성
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenDTO {

    private String accessToken;

    private String refreshToken;

}
