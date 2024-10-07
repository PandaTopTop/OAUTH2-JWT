package com.dzomo.security.securityEx.controllers;

import com.dzomo.security.securityEx.models.Student;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class StudentController {

    List<Student> studentList =  new ArrayList<Student>(List.of(
            new Student(2,"Rob",1),
            new Student(4,"Bob",3))
    );
    @GetMapping("/students")
    public List<Student> students() {
        return studentList;
    }


    @GetMapping("/csrf")
    public CsrfToken csrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }


    @PostMapping("/student")
    public Student addStudent(@RequestBody Student student){

        studentList.add(student);
        return student;
    }
}
