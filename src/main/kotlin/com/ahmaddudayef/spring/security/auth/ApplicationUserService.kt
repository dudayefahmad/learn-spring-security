package com.ahmaddudayef.spring.security.auth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class ApplicationUserService @Autowired constructor(
    @Qualifier("fake")
    private val applicationUserDao: ApplicationUserDao
) : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        return applicationUserDao
            .selectApplicationUserByUsername(username)
            .orElseThrow {
                UsernameNotFoundException(
                    String.format(
                        "Username %s not found",
                        username
                    )
                )
            }
    }
}