package br.desafio.pitang.resource;

import java.security.Principal;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import br.desafio.pitang.jwt.TokenUtil;
import br.desafio.pitang.model.Usuario;
import br.desafio.pitang.security.exception.InvalidFieldsException;
import br.desafio.pitang.service.UsuarioService;




@RestController
public class UsuarioResource {
	
	@Autowired
	private UsuarioService usuarioService;

	
	@PostMapping("/singup")
	public ResponseEntity<Object>singup(@RequestBody @Valid Usuario usuario) {
		Usuario usuarioSalvo = usuarioService.singup(usuario);
		
		return ResponseEntity.ok("token: " + TokenUtil.getToken(usuarioSalvo.getEmail()));
	} 
	
	@PostMapping("/singin")
	public ResponseEntity<Object>singup(@RequestBody  AuthenticationRequest usuarioRequest) {
	    if(usuarioRequest == null || usuarioRequest.getEmail() == null || usuarioRequest.getPassword() == null)
	  		   throw new InvalidFieldsException("Missing Fields");
	    
	    Usuario usuarioSalvo =  usuarioService.singin(usuarioRequest.convertToUsuario());
		return ResponseEntity.ok(TokenUtil.getToken(usuarioSalvo.getEmail()));
	} 
	
	@GetMapping(path = "/me")
    public ResponseEntity<Usuario> me(Principal principal) {
        return ResponseEntity.ok(usuarioService.findByEmailAddress(principal.getName()));
    }
	
	
}
