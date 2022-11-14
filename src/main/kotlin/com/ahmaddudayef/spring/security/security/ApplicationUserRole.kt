package com.ahmaddudayef.spring.security.security

import com.ahmaddudayef.spring.security.security.ApplicationUserPermission.*
import com.google.common.collect.Sets
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.util.stream.Collectors

enum class ApplicationUserRole(private val permissions: Set<ApplicationUserPermission>) {
    STUDENT(Sets.newHashSet<ApplicationUserPermission>()),
    ADMIN(
        Sets.newHashSet(
            COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WRITE
        )
    ),
    ADMINTRAINEE(
        Sets.newHashSet(COURSE_READ, STUDENT_READ)
    );

    val grantedAuthorities: Set<SimpleGrantedAuthority>
        get() {
            val permissions = permissions.stream()
                .map { permission: ApplicationUserPermission ->
                    SimpleGrantedAuthority(
                        permission.permission
                    )
                }
                .collect(Collectors.toSet())
            permissions.add(SimpleGrantedAuthority("ROLE_$name"))
            return permissions
        }
}