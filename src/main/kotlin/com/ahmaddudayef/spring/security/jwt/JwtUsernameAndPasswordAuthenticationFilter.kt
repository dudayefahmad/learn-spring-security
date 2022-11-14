package com.ahmaddudayef.spring.security.jwt

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import java.io.IOException
import java.time.LocalDate
import java.util.*
import javax.crypto.SecretKey
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class JwtUsernameAndPasswordAuthenticationFilter constructor(
    authenticationManager: AuthenticationManager,
    private val jwtConfig: JwtConfig,
    private val secretKey: SecretKey
) : UsernamePasswordAuthenticationFilter(authenticationManager) {


    @Throws(AuthenticationException::class)
    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        try {
            val (username, password) = jacksonObjectMapper().readValue(request?.inputStream, UsernameAndPasswordAuthenticationRequest::class.java)
            println("Data Auth : $username, $password")
            val authentication = UsernamePasswordAuthenticationToken(username, password)
            return authenticationManager.authenticate(authentication)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain?,
        authResult: Authentication?
    ) {

        val key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecure"

        val token = Jwts.builder()
            .setSubject(authResult?.name)
            .claim("authorities", authResult?.authorities)
            .setIssuedAt(Date())
            .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.tokenExpirationAfterDays.toLong())))
//            .signWith(Keys.hmacShaKeyFor(key.toByteArray()))
            .signWith(secretKey)
            .compact()

//        response?.addHeader("Authorization", "Bearer $token")
        response?.addHeader(jwtConfig.authorizationHeader, jwtConfig.tokenPrefix + token)
    }
}