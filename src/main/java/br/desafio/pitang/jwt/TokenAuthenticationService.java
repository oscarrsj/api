package br.desafio.pitang.jwt;

import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenAuthenticationService {
	
	
	
	static void addAuthentication(HttpServletResponse response, String username) {
		String JWT = Jwts.builder()
				.setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + TokenUtil.EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, TokenUtil.SECRET)
				.compact();
		
		response.addHeader(TokenUtil.HEADER_STRING, TokenUtil.TOKEN_PREFIX + " " + JWT);
	}
	
	static Authentication getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(TokenUtil.HEADER_STRING);
		
		if (token != null) {
			// faz parse do token
			String user = Jwts.parser()
					.setSigningKey(TokenUtil.SECRET)
					.parseClaimsJws(token.replace(TokenUtil.TOKEN_PREFIX, ""))
					.getBody()
					.getSubject();
			
			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());
			}
		}
		return null;
	}
	
	
	
}