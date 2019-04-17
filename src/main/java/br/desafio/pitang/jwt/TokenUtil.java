package br.desafio.pitang.jwt;

import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenUtil {
	// EXPIRATION_TIME = 10 dias
	public	static final long EXPIRATION_TIME = 860_000_000;
	public	static final String SECRET = "MySecret";
	public	static final String TOKEN_PREFIX = "Bearer";
	public	static final String HEADER_STRING = "Authorization";
	
	public static String getToken(String username) {
		return Jwts.builder().setSubject(username).setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
		.signWith(SignatureAlgorithm.HS512, SECRET).compact();
	}
}
