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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@RestController
public class SecurityController {
	
	private final Logger log = LoggerFactory.getLogger(getClass());
	private final AuthenticationManager authenticationManager;
	SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
	
	public SecurityController(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@GetMapping("/")
	public String index() {
		log.info("index Controller");
		return "index";
	}
	
	@GetMapping("/page")
	public String page() {
		log.info("로그인 성공");
		return "page";
	}
	
	@PostMapping("/login")
	public String login(@RequestBody Map<String, Object> loginRequest) {
		Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.get("username"), loginRequest.get("password"));
		Authentication authenticationResponse =	this.authenticationManager.authenticate(authenticationRequest);
		SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
		UserDetails user = (UserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("login userName= ", user.getUsername());
        return "redirect:/page";
	}

	@PostMapping("/logout")
	public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
		logoutHandler.logout(request, response, authentication);
		log.info("logOut");
		return "logOut";
	}
	
	@GetMapping("notFound")
	public void notFound() throws Exception {
		throw new Exception("404");
	}
	
}
