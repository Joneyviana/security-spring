package com.security.auth;

public class LoginDTOResponse {
	private String token;
	private String acesso;
	public String getToken() {
		return token;
	}
	public LoginDTOResponse(String token, String acesso) {
		this.token = token;
		this.acesso = acesso;
	}
	public LoginDTOResponse() {
		
	}
	
	public void setToken(String token) {
		this.token = token;
	}
	public String getAcesso() {
		return acesso;
	}
	public void setAcesso(String acesso) {
		this.acesso = acesso;
	} 

}
