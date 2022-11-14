package com.ahmaddudayef.spring.security.jwt

import com.google.common.net.HttpHeaders
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding


@ConfigurationProperties(prefix = "application.jwt")
@ConstructorBinding
data class JwtConfig(
    val secretKey: String,
    val tokenPrefix: String,
    val tokenExpirationAfterDays: Int,
) {
    val authorizationHeader: String
        get() = HttpHeaders.AUTHORIZATION
}