package br.desafio.pitang.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;

import br.desafio.pitang.config.service.UsuarioDetailService;

/**
 * SecurityConfig
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	

  @Autowired
  private UsuarioDetailService usuarioDetailService;

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.cors().configurationSource(r -> new CorsConfiguration().applyPermitDefaultValues());
    http.csrf()//
        .disable()//
        .authorizeRequests()//
        .antMatchers(HttpMethod.POST, "/singup").permitAll()//
        .antMatchers(HttpMethod.POST, "/singin").permitAll()//
        .anyRequest().authenticated()//
        .and()//
        .addFilter(new JWTLoginFilter(authenticationManager()))//
        .addFilter(new JWTAuthenticationFilter(authenticationManager(), usuarioDetailService));
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(usuarioDetailService)//
        .passwordEncoder(new BCryptPasswordEncoder());
  }

  // @Autowired
  // protected void configure(AuthenticationManagerBuilder auth) throws Exception
  // {
  // auth.inMemoryAuthentication()//
  // .withUser("carlos").password("{noop}12345").roles("USER", "ADMIN")//
  // .and()//
  // .withUser("henrique").password("{noop}12345").roles("USER");
  // }
}