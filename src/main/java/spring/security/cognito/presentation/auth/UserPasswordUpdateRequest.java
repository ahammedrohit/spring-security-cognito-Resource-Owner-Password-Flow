package spring.security.cognito.presentation.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.lang.NonNull;
import spring.security.cognito.application.user.AuthenticatedChallengeDTO;
import spring.security.cognito.config.annotations.PasswordValueMatch;
import spring.security.cognito.config.annotations.ValidPassword;


@PasswordValueMatch.List({
        @PasswordValueMatch(
                field = "password",
                fieldMatch = "passwordConfirm",
                message = "Passwords do not match!"
        )
})
@AllArgsConstructor()
@NoArgsConstructor
@Getter
@Setter
@ToString
@EqualsAndHashCode(callSuper = true)
public class UserPasswordUpdateRequest extends AuthenticatedChallengeDTO {

  @NonNull
  @NotBlank(message = "New password is mandatory")
  private String password;


  @ValidPassword
  @NonNull
  @NotBlank(message = "Confirm Password is mandatory")
  private String passwordConfirm;
}