package com.ahmaddudayef.spring.security.jwt

import com.google.common.base.Strings
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.util.stream.Collectors
import javax.crypto.SecretKey
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class JwtTokenVerifier constructor(
    private val jwtConfig: JwtConfig,
    private val secretKey: SecretKey
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
//        val authorizationHeader = request.getHeader("Authorization")
        val authorizationHeader = request.getHeader(jwtConfig.authorizationHeader)

//        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.tokenPrefix)) {
            filterChain.doFilter(request, response);
            return
        }

//        val token = authorizationHeader.replace("Bearer ", "")
        val token = authorizationHeader.replace(jwtConfig.tokenPrefix, "")

        try {
//            val secretKey = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecure"

            val claimsJws = Jwts.parserBuilder()
//                .setSigningKey(Keys.hmacShaKeyFor(secretKey.toByteArray()))
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);

            val body = claimsJws.body

            val username = body.subject

            val authorities = body["authorities"] as List<Map<String, String>>

            val simpleGrantedAuthorities: Set<SimpleGrantedAuthority> =
                authorities.stream()
                .map { m -> SimpleGrantedAuthority(m["authority"]) }
                .collect(Collectors.toSet())

            val authentication: Authentication = UsernamePasswordAuthenticationToken(
                username,
                null,
                simpleGrantedAuthorities
            )

            SecurityContextHolder.getContext().authentication = authentication
        } catch (e: JwtException) {
            throw IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        filterChain.doFilter(request, response);
    }
}