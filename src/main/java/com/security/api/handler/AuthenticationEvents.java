package com.security.api.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/* 
 * 인증 이벤트 처리 핸들러
*/
@Component
public class AuthenticationEvents {

	private final Logger log = LoggerFactory.getLogger(getClass());
	
	/*
	 * @EventListener : 스프링 4.2 이상 사용 가능
	 * AuthenticationEventPublisher bean 등록 후 사용 가능
	 */
	@EventListener
	public void onSuccessHandlers(AuthenticationSuccessEvent event) {
		Authentication authentication = event.getAuthentication();
		log.info("Success", authentication);
	}
	
	@EventListener
	public void onFailureHandler(AbstractAuthenticationFailureEvent event) {
		Authentication authentication = event.getAuthentication();
		log.info("Failure", authentication);
	}
}
