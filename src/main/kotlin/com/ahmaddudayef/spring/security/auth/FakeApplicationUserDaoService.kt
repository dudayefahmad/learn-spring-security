package com.ahmaddudayef.spring.security.auth

import com.ahmaddudayef.spring.security.security.ApplicationUserRole
import com.ahmaddudayef.spring.security.security.ApplicationUserRole.*
import com.google.common.collect.Lists
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Repository
import java.util.*

@Repository("fake")
class FakeApplicationUserDaoService @Autowired constructor(
    private val passwordEncoder: PasswordEncoder
) : ApplicationUserDao {

    override fun selectApplicationUserByUsername(username: String): Optional<ApplicationUser> {
        return getApplicationUsers()
            .stream()
            .filter { applicationUser ->
                username == applicationUser.username
            }
            .findFirst()
    }


    private fun getApplicationUsers(): List<ApplicationUser> {
        return Lists.newArrayList(
            ApplicationUser(
                "naruto",
                passwordEncoder.encode("password"),
                STUDENT.grantedAuthorities,
                isAccountNonExpired = true,
                isAccountNonLocked = true,
                isCredentialsNonExpired = true,
                isEnabled = true
            ),
            ApplicationUser(
                "sakura",
                passwordEncoder.encode("password"),
                STUDENT.grantedAuthorities,
                isAccountNonExpired = true,
                isAccountNonLocked = true,
                isCredentialsNonExpired = true,
                isEnabled = true
            ),
            ApplicationUser(
                "sasuke",
                passwordEncoder.encode("password123"),
                ADMINTRAINEE.grantedAuthorities,
                isAccountNonExpired = true,
                isAccountNonLocked = true,
                isCredentialsNonExpired = true,
                isEnabled = true
            ),
            ApplicationUser(
                "kakashi",
                passwordEncoder.encode("password123"),
                ADMIN.grantedAuthorities,
                isAccountNonExpired = true,
                isAccountNonLocked = true,
                isCredentialsNonExpired = true,
                isEnabled = true
            )
        )
    }
}