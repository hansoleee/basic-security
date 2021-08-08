package com.hansoleee.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@Controller
@RequiredArgsConstructor
public class MainController {

    @GetMapping("/login")
    public String login(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "login";
    }

    @GetMapping({"/", "/index"})
    @ResponseBody
    public String index(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "index";
    }

    @GetMapping("/home")
    @ResponseBody
    public String home(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "home";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "user";
    }

    @GetMapping("/system")
    @ResponseBody
    public String system(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "system";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "admin";
    }

    @GetMapping("/denied")
    @ResponseBody
    public String denied(HttpServletRequest request) {
        log.info(request.getRequestURL().toString() + " " + request.getMethod());
        return "denied";
    }
}
