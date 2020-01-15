package com.security.auth;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Length;

public class EmailDTO {
	
	@NotEmpty(message = "O campo email não pode ser vazio.")
	@Length(min = 5, max = 200, message = "O email deve conter entre 5 e 200 caracteres.")
	@Email(message = "Email inválido!")
	private String email;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

}
