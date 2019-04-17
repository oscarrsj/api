package br.desafio.pitang.config;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.desafio.pitang.model.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * JWTAuthenticator
 */
public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {
	static final long EXPIRATION_TIME = 3600000;
	
    private AuthenticationManager authenticationManager;

    public JWTLoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        Usuario usuario;
        try {
            usuario = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
            return this.authenticationManager//
                    .authenticate(//
                            new UsernamePasswordAuthenticationToken(usuario.getEmail(), usuario.getPassword()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        String token =  	getToken(((User) authResult.getPrincipal()).getUsername());

        response.addHeader("Authorization", "Bearer " + token);
    }

    
    public static String getToken(String chave) {
    	return   	Jwts//
    	        .builder()//
    	        .setSubject(chave)//
    	        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))//
    	        .signWith(SignatureAlgorithm.HS512, "SECRET").compact();
    }
}