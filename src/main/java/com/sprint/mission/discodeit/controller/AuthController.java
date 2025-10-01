package com.sprint.mission.discodeit.controller;

import com.sprint.mission.discodeit.auth.DiscodeitUserDetails;
import com.sprint.mission.discodeit.dto.data.UserDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/csrf-token")
    public ResponseEntity<Void> getCsrfToken(CsrfToken csrfToken) { // CsrfToken 파라미터를 메서드 인자로 선언하면, HandlerMethodArgumentResolver를 통해 자동으로 주입됨
        String tokenValue = csrfToken.getToken(); // GET 요청에는 CSRF 인증이 이루어지지 않기 때문에 토큰 초기화 X, 따라서 명시적으로 메소드에서 토큰 호출
        log.debug("CSRF 토큰 요청: {}", tokenValue);

        return ResponseEntity
                .status(HttpStatus.NON_AUTHORITATIVE_INFORMATION)
                .build();
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser(@AuthenticationPrincipal DiscodeitUserDetails userDetails) {

        UserDto userDto = userDetails.getUserDto();
        log.debug("Current User: {} / {}", userDto.username(), userDto.email());

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userDto);
    }
}
