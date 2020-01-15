package com.security.auth;

import java.io.Serializable;

public class LoginDto implements Serializable{
    /**
	 * 
	 */
	private static final long serialVersionUID = 3334913169453891285L;
	private String email;
    private String password;

    LoginDto(String email,String password) {
        this.setEmail(email);
        this.setPassword(password);
    }
    public LoginDto() {
    	
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
}
