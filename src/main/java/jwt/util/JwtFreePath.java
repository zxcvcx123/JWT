package org.daeng2go.daeng2go_server.jwt.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * 업 무 : JwtFreePath 클래스
 * 설 명 : 토큰을 검증하지 않는 비회원도 접속 가능한 URL
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모    			2024-06-10   		최초작성
 */
public enum JwtFreePath {

    /* 여기에 비회원도 사용 가능한 API URI 설정 */
    PATH(Arrays.asList(
            "/member/dec/add",              // 가입할때 복호화
            "/member/dec/find",             // 패스워드 찾기
            "/member/idcheck",              // 중복 아이디 찾기
            "/pet/register/check",          // 반려견등록번호 중복확인
            "/member/identity/check",       // 휴대폰번호 확인
            "/member/add",                  // 회원가입
            "/token",                       // 로그인, 재발급
            "/breed/",                      // 견종도감
            "/tags",                        // 해시태그
            "/code/",                       // 코드 불러오기
            "/fortune/info",                // 오늘의 운세
            "/compatibility/info",          // 궁합
            "/file/image/upload",           // MBTI
            "/mbti/mbtis",
            "/manse/get",                   // 만세력
            "/identity",                    // NICE API
            "/member/find/id",              // 아이디 찾기
            "/member/find/password",        // 비밀번호 재설정
            "/search/main/v1",              // 검색
            "/admin/token",                 // 관리자 로그인, 재발급
            "/user",                        // 테스트
            "/test"                         // 테스트
    ));

    /* 필드 선언 */
    private final List<String> freePath;

    /* 생성자 */
    JwtFreePath(List<String> freePath) {
        this.freePath = freePath;
    }

    /* getter 활용해 PATH 활용하기 */
    public List<String> getFreePath() {
        return freePath;
    }
}
