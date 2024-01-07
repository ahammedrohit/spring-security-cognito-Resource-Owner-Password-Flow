package spring.security.cognito.presentation.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UserSignUpRequest {

  @NotBlank
  @NotNull
  @Email
  private String email;

//  @ValidPassword
  private String password;

  @NotBlank
  @NotNull
  private String name;

//  @NotNull
//  @NotEmpty
//  private Set<String> roles;
}
