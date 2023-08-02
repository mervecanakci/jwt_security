package com.security.springsecurity;

import com.security.springsecurity.auth.AuthenticationService;
import com.security.springsecurity.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.security.springsecurity.user.Role.ADMIN;
import static com.security.springsecurity.user.Role.MANAGER;
@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
        @Bean
        public CommandLineRunner commandLineRunner(
                AuthenticationService service
	) {
            return args -> {
                var admin = RegisterRequest.builder()
                        .firstname("merve")
                        .lastname("canakcı")
                        .email("merve@mail.com")
                        .password("password")
                        .role(ADMIN)
                        .build();
                System.out.println("Admin token: " + service.register(admin).getAccessToken());

                var manager = RegisterRequest.builder()
                        .firstname("ahmet")
                        .lastname("mehmet")
                        .email("ahmet@mail.com")
                        .password("password")
                        .role(MANAGER)
                        .build();
                System.out.println("Manager token: " + service.register(manager).getAccessToken());

            };
        }


    }


