package com.security.auth;


import java.io.Serializable;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import com.generic.crud.Exception.ObjectNotFoundException;
import com.security.config.ApiResponse;
import com.security.config.JWTUtils;
import com.utils.email.EmailService;


@RestController
@RequestMapping(value = "api/auth")
@CrossOrigin(origins = "*")
public class AuthController {
	
	  @Autowired
	  private AuthenticationManager authenticationManager;
	  
	  @Autowired
	  private EmailService emailService;
	  
	  @Autowired
	  private UserRepository userRepository;
	  
	  @Autowired
	  private JWTUtils jwtUtils;


	@PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_UTF8_VALUE, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public ResponseEntity<?> login (@RequestBody LoginDto login){ 
		UsernamePasswordAuthenticationToken authenticate = new UsernamePasswordAuthenticationToken(
                login.getEmail(), login.getPassword());
		String acesso = "";
		try {
		org.springframework.security.core.Authentication authentication = authenticationManager.authenticate(authenticate);
	        SecurityContextHolder.getContext().setAuthentication(authentication);
	    for (GrantedAuthority auth : authentication.getAuthorities()) {
	    	       acesso += auth.getAuthority().replace("ROLE_", "")+" ";
	               break;
	            }
		}
	    catch(Exception e) {
	    	ApiResponse response = new ApiResponse(401, "Unauthorised");
	        response.setMessage("Unauthorised");
	    	return new ResponseEntity<>(response,HttpStatus.UNAUTHORIZED);
	    }
	   
	    //System.out.println("esse é o nome "+ authenticate.getName());
	    String token = jwtUtils.generateToken(authenticate.getName());
	    

		LoginDTOResponse response = new LoginDTOResponse(token,acesso.trim());
	    return new ResponseEntity<>(response,HttpStatus.ACCEPTED);
	}
	
	@GetMapping(value="/users")
	@PreAuthorize("hasAnyRole('MASTER','TERAPEUTA')")
	public List<UserDto> listaUsers() {
		return userRepository.listar().stream().map(UserDto::new).collect(Collectors.toList());
	}
	
	@PostMapping(value="/recuperarSenha")
	public String recuperarSenha(@Valid @RequestBody EmailDTO emailDTO) {
		Optional<User> user  = userRepository.findByEmail(emailDTO.getEmail());
		if(!user.isPresent()) {
			throw new ObjectNotFoundException("email não encontrado");
		}
		user.get().setTokenRecuperarSenha(jwtUtils.generateToken(emailDTO.getEmail()));
		userRepository.save(user.get());
		emailService.sendSimpleMessage(emailDTO.getEmail(),"Recuperar Senha", 
				user.get().getTokenRecuperarSenha());
		return "enviado";
	}
	
	@PostMapping(value="/novaSenha")
	public String novaSenha(@Valid @RequestBody AlterarSenhaDTO alterarSenhaDTO) {
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		Optional<User> user  = userRepository.findByEmail(alterarSenhaDTO.getEmail());
		if(!user.isPresent()) {
			throw new ObjectNotFoundException("email não encontrado");
		}
		if(user.get().getTokenRecuperarSenha() != null && user.get().getTokenRecuperarSenha().equals(alterarSenhaDTO.getToken())) {
			user.get().setPassword(passwordEncoder.encode(alterarSenhaDTO.getNovaSenha()));
		    user.get().setTokenRecuperarSenha(null);
		    userRepository.save(user.get());
		    return "Senha Alterada";
		}
		return "Não foi possivel trocar a senha";
	}
	@PostMapping("/logout")
	public String  deslogar(HttpServletRequest request, HttpServletResponse response){
	    org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null)
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        return "Voce foi deslogado";
	}
}

class CadastroDto implements Serializable {
	private static final long serialVersionUID = 3234913169453891288L;
	private String email;
    private String password;
    private String name;
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
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
}
