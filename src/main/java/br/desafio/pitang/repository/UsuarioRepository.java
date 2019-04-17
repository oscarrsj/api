package br.desafio.pitang.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import br.desafio.pitang.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
	Usuario findByEmailAddress(String emailAddress);

	@Query("select u from Usuario u where u.email = :emailAddress and u.password = :password")
	Usuario findByEmailAndPasswoward(@Param("emailAddress") String emailAddress, @Param("password")  String password);
}
