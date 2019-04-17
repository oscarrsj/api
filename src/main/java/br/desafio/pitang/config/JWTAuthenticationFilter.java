package br.desafio.pitang.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import br.desafio.pitang.config.service.UsuarioDetailService;
import io.jsonwebtoken.Jwts;

/**
 * JWTAuthorizationFilter
 */
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

  @Autowired
  private UsuarioDetailService usuarioDetailService;

  public JWTAuthenticationFilter(AuthenticationManager authenticationManager,
      UsuarioDetailService usuarioDetailService) {
    super(authenticationManager);
    this.usuarioDetailService = usuarioDetailService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {
    try {
      String header = request.getHeader("Authorization");

      if (header == null || !header.startsWith("Bearer") ){
        chain.doFilter(request, response);
        return;
      }

      UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(request);
      SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      chain.doFilter(request, response);
    } catch (InvalidJwtAuthenticationException e) {
      throw new InvalidJwtAuthenticationException(e.getMessage());
    }
  }

  private UsernamePasswordAuthenticationToken getAuthenticationToken(HttpServletRequest request) {
    String token = request.getHeader("Authorization");

    if (token == null) {
      return null;
    }
    String username = "";
    username = Jwts//
        .parser()//
        .setSigningKey( "SECRET")//
        .parseClaimsJws(token.replace("Bearer ", ""))//
        .getBody()//
        .getSubject();

    UserDetails userDetails = usuarioDetailService.loadUserByUsername(username);

    if (username != null) {
      return new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
    }
    return null;
  }
}