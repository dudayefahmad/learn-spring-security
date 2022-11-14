package com.ahmaddudayef.spring.security.auth

import java.util.*

interface ApplicationUserDao {

    fun selectApplicationUserByUsername(username: String): Optional<ApplicationUser>
}