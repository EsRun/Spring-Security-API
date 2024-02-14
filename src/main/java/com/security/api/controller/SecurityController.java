package com.security.api.controller;

import java.net.http.HttpRequest;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
public class SecurityController {
	
	private final Logger log = LoggerFactory.getLogger(getClass());
	
	private final AuthenticationManager authenticationManager;

	public SecurityController(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@GetMapping("/")
	public String index() {
		log.info("index Controller");
		return "index";
	}
	
	@PostMapping("/login")
	public String login(@RequestBody Map<String, Object> loginRequest) {
		Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.get("username"), loginRequest.get("password"));
		Authentication authenticationResponse =	this.authenticationManager.authenticate(authenticationRequest);
			
        
		SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        log.info("login userName= ", SecurityContextHolder.getContext().getAuthentication());
        return "login";
        
		
	}

	@PostMapping("/logout")
	public String logout() {
		log.info("logOut");
		return "logOut";
	}
	
}
