package org.example.springsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class DemoController {

    @GetMapping()
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello World");
    }
}
