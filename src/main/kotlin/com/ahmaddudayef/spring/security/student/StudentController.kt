package com.ahmaddudayef.spring.security.student

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("api/v1/students")
class StudentController {

    private val students: List<Student> = listOf(
        Student(1, "Naruto"),
        Student(2, "Sakura"),
        Student(3, "Sasuke"),
        Student(4, "Kakashi")
    )

    @GetMapping(path = ["{studentId}"])
    fun getStudent(@PathVariable("studentId") studentId: Int): Student {
        return students.stream()
            .filter { student ->
                studentId == student.studentId
            }
            .findFirst()
            .orElseThrow {
                IllegalStateException(
                    "Student $studentId does not exists"
                )
            }
    }

}