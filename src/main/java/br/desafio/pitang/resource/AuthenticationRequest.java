package br.desafio.pitang.resource;

import java.io.Serializable;

import br.desafio.pitang.model.Usuario;
import br.desafio.pitang.security.exception.InvalidFieldsException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequest implements Serializable {
    private String email;
    private String password;
    
   public Usuario convertToUsuario() {
	  
	   
	   Usuario usuario = new Usuario();
	   usuario.setEmail(email);
	   usuario.setPassword(password);
	   
	   usuario.encriptPassowrd();
	   
	   return usuario;
   }

}
