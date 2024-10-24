package org.daeng2go.daeng2go_server.jwt.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.daeng2go.daeng2go_server.common.controller.BaseController;
import org.daeng2go.daeng2go_server.common.util.response.ResponseUtils;
import org.daeng2go.daeng2go_server.common.util.response.dto.ResponseDTO;
import org.daeng2go.daeng2go_server.jwt.dto.TokenDTO;
import org.daeng2go.daeng2go_server.jwt.service.JwtTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 업 무 : JwtTokenController
 * 설 명 : Jwt refresh 토큰 재발급
 *
 * Revision History
 * Author            	Date              	Description
 * ---------------   	--------------    	------------------
 * 정정모     			2024-06-03   		최초작성
 */
@RestController
@RequiredArgsConstructor
public class JwtTokenController extends BaseController {

    private final JwtTokenService jwtTokenService;


    /**
     * @Method	- reissueToken
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- access, refresh 토큰 재발급
     * @param request HttpRequest 오는 데이터들
     * @Return	- ResponseEntity
     */
    @RequestMapping(value = "/token/reissue", method = RequestMethod.POST)
    public ResponseEntity reissueToken(HttpServletRequest request){
        // 토큰 검증
        return sendSuccess(jwtTokenService.checkToken(request));
    }

    /**
     * @Method	- reissueToken
     * @Date	- 24.06.03
     * @Writter	- 정정모
     * @EditHistory	-
     * @Discript	- access, refresh 토큰 재발급
     * @param request HttpRequest 오는 데이터들
     * @Return	- ResponseEntity
     */
    @RequestMapping(value = "/admin/token/reissue", method = RequestMethod.POST)
    public ResponseEntity reissueAdminToken(HttpServletRequest request){
        // 토큰 검증
        return sendSuccess(jwtTokenService.checkAdminToken(request));
    }



}
