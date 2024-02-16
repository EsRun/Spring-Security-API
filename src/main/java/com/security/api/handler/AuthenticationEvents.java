package com.security.api.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {

	private final Logger log = LoggerFactory.getLogger(getClass());
	
	@EventListener
	public void onSuccess(AuthenticationEvents success) {
		log.info("Success");
	}
	
	@EventListener
	public void onFailure(AuthenticationEvents fialures) {
		log.info("Failure");
	}
}
