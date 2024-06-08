package io.github.devruibin.securingspring;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/test")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> test(
            Authentication authentication,
            Principal principal,
            @AuthenticationPrincipal User u){
        User user = (User)authentication.getPrincipal();
        System.out.println(user.getFullname());
        System.out.println(u.getFullname());
        System.out.println(principal.getName());
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        User u2 = (User)authentication.getPrincipal();
        System.out.println(u2.getFullname());
        return ResponseEntity.ok(principal.getName());
    }



}
