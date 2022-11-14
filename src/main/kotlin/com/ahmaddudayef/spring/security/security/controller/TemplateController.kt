package com.ahmaddudayef.spring.security.security.controller

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping


@Controller
@RequestMapping("/")
class TemplateController {

    @GetMapping("login")
    fun getLogin(): String {
        return "login"
    }

    @GetMapping("courses")
    fun getCourses(): String {
        return "courses"
    }

}