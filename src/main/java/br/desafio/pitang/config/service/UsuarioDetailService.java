package br.desafio.pitang.config.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import br.desafio.pitang.model.Usuario;
import br.desafio.pitang.service.UsuarioService;

/**
 * CustomUserDetailService
 */
@Component
public class UsuarioDetailService implements UserDetailsService {

    @Autowired
    private UsuarioService usuarioService;

    @Override
    public UserDetails loadUserByUsername(String emailAdress) throws UsernameNotFoundException {
        Assert.notNull(emailAdress, "Missing fields");
        Usuario usuario = Optional.ofNullable(usuarioService.findByEmailAddress(emailAdress))
                .orElseThrow(() -> new UsernameNotFoundException("Invalid e-mail or password."));

        return new User(//
                usuario.getEmail(), //
                usuario.getPassword(), //
                AuthorityUtils.createAuthorityList("ADMIN"));
    }

}