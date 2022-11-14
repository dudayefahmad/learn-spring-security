package com.ahmaddudayef.spring.security.security

enum class ApplicationUserPermission(val permission: String) {
    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write")
}