package br.desafio.pitang.service;

import org.jboss.jandex.TypeTarget.Usage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.desafio.pitang.model.Usuario;
import br.desafio.pitang.repository.UsuarioRepository;
import br.desafio.pitang.security.exception.InvalidFieldsException;

@Service
public class UsuarioService {
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	
	public Usuario findByEmailAddress(String emailAddress) {
		return usuarioRepository.findByEmailAddress(emailAddress);
	}
	
	public Usuario findByEmailAndPasswoward(String emailAddress, String password) {
		return usuarioRepository.findByEmailAndPasswoward(emailAddress, password);
	}
	
	
	public Usuario singup(Usuario usuario) {
		if(findByEmailAddress(usuario.getEmail()) != null) {
			throw new InvalidFieldsException("E-mail already exists");
		}
		
		if(!usuario.validarFields()) {
			throw new InvalidFieldsException("Missing fields");
		}
		
		if(usuario.getId() != null) {
			throw new InvalidFieldsException("ID preenchido");
		}
		
		usuario.encriptPassowrd();
		
		Usuario UsuarioSalvo = usuarioRepository.save(usuario);
		
	
		return UsuarioSalvo;
	}


	public Usuario singin(Usuario usuario) {
		Usuario usuarioPesquisado = findByEmailAndPasswoward(usuario.getEmail() , usuario.getPassword());
		
		if(usuarioPesquisado == null) {
			throw new InvalidFieldsException("Invalid e-mail or password");
		}
		
		return usuarioPesquisado;
	}
}
