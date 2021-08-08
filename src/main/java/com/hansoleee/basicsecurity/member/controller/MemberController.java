package com.hansoleee.basicsecurity.member.controller;

import com.hansoleee.basicsecurity.member.domain.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@Controller
@RequiredArgsConstructor
public class MemberController {

    @PostMapping("/login")
    public void login(Member member,
                      HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod() + " member: {}", member);
    }
}
