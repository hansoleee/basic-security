package com.hansoleee.basicsecurity.config.security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SecurityController {

    @GetMapping("/security")
    public Object security() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        log.info("principal :{}", principal.toString());
        return authentication;
    }

    @GetMapping("/thread")
    public String thread() {
        new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // authentication = null;
        }).start();

        return "thread";
    }
}
