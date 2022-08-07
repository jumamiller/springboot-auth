package com.bikebuka.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @RequestMapping("api/v1/home")
    public String welcomeMessage(@RequestParam(value = "message",defaultValue = "Welcome to Spring auth") String message) {
        return message;
    }
}
