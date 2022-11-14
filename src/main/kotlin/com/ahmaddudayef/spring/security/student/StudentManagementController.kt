package com.ahmaddudayef.spring.security.student

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*


@RestController
@RequestMapping("management/api/v1/students")
class StudentManagementController {

    private val students: List<Student> = listOf(
        Student(1, "Naruto"),
        Student(2, "Sakura"),
        Student(3, "Sasuke"),
        Student(4, "Kakashi")
    )

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    fun getAllStudents(): List<Student> {
        println("getAllStudents")
        return students
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    fun registerNewStudent(@RequestBody student: Student) {
        println("registerNewStudent")
        println(student)
    }

    @DeleteMapping(path = ["{studentId}"])
    @PreAuthorize("hasAuthority('student:write')")
    fun deleteStudent(@PathVariable("studentId") studentId: Int) {
        println("deleteStudent")
        println(studentId)
    }

    @PutMapping(path = ["{studentId}"])
    @PreAuthorize("hasAuthority('student:write')")
    fun updateStudent(@PathVariable("studentId") studentId: Int, @RequestBody student: Student) {
        println("updateStudent")
        println(String.format("%s %s", studentId, student))
    }

}