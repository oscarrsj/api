package br.desafio.pitang.model;

import java.io.Serializable;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Entity
@NamedQuery(name = "Usuario.findByEmailAddress",
query = "select u from Usuario u where u.email = ?1")
public class Usuario implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy= GenerationType.IDENTITY)
	private Long id;
	
	private String firstName;
	
	private String lastName;
	
	@NotBlank(message = "Email é necessário")
	@Email()
	private String email;
	
	private String password;
	
	@OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
	@JoinColumn(name = "USUARIO_ID",referencedColumnName   = "id")
	@Valid
	private List<Telefone> phones;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public List<Telefone> getPhones() {
		return phones;
	}

	public void setPhones(List<Telefone> phones) {
		this.phones = phones;
	}

	public void encriptPassowrd() {
		if(password != null)
			new BCryptPasswordEncoder().encode(password);
	}
	
	public boolean validarFields() {
		if(firstName == null  || lastName == null || password == null)
			return false;
		
		return true;
	}
}
