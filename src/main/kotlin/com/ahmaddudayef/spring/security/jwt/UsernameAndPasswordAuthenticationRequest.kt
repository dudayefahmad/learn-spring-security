package com.ahmaddudayef.spring.security.jwt

data class UsernameAndPasswordAuthenticationRequest(
    val username: String,
    val password: String
)