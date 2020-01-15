package com.security.auth;


import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;


import java.util.Collection;
import java.util.List;

@Entity
@Table(name="users")
public class User
{
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;
    @Column(nullable=false)
    @NotEmpty()
    private String name;
    @Column(nullable=false, unique=true)
    @NotEmpty
    @Email(message="{errors.invalid_email}")
    private String email;
    @Column(nullable=false)
    @NotEmpty
    @Size(min=4)
    private String password;
    
    private String tokenRecuperarSenha;

    @ManyToMany(cascade=CascadeType.MERGE)
    @JoinTable(
            name="user_role",
            joinColumns={@JoinColumn(name="USER_ID", referencedColumnName="ID")},
            inverseJoinColumns={@JoinColumn(name="ROLE_ID", referencedColumnName="ID")})
    private List<Role> roles;

    public Long getId()
    {
        return id;
    }
    public void setId(Long id)
    {
        this.id = id;
    }
    public String getName()
    {
        return name;
    }
    public void setName(String name)
    {
        this.name = name;
    }
    public String getEmail()
    {
        return email;
    }
    public void setEmail(String email)
    {
        this.email = email;
    }
    public String getPassword()
    {
        return password;
    }
    public void setPassword(String password)
    {
        this.password = password;
    }
    public List<Role> getRoles()
    {
        return roles;
    }
    public void setRoles(List<Role> roles)
    {
        this.roles = roles;
    }
	public String getTokenRecuperarSenha() {
		return tokenRecuperarSenha;
	}
	public void setTokenRecuperarSenha(String tokenRecuperarSenha) {
		this.tokenRecuperarSenha = tokenRecuperarSenha;
	}

}
class UserDto {
	private String name;
	private String email;
	private String role;
	private Long id;
	
	public UserDto(User user) {
		this.setName(user.getName());
		this.setEmail(user.getEmail());
		if(!user.getRoles().isEmpty()) {
		    this.setRole(user.getRoles().get(0).getName());
		}
		this.setId(user.getId());
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public Long  getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}	
}

