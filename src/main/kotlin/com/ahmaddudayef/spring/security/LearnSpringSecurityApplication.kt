package com.ahmaddudayef.spring.security

import com.ahmaddudayef.spring.security.jwt.JwtConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(
	JwtConfig::class
)
class LearnSpringSecurityApplication

fun main(args: Array<String>) {
	runApplication<LearnSpringSecurityApplication>(*args)
}
