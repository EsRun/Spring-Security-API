package com.security.api.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomLogoutHandler implements LogoutHandler{
	
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		
		System.out.println("로그아웃 핸들러");
		System.out.println(authentication);
		
	}
}
