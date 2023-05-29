package com.example.oauth2.oauth2demo.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class DemoController {
    @GetMapping("/")
    public String group1(Principal principal) {
        return "Hello group 1" + principal;
    }
}
