package spring.security.cognito.application.user;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.lang.NonNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticatedChallengeDTO {

  @NotBlank
  private String sessionId;

  @NonNull
  @NotBlank(message = "username is mandatory")
  private String username;

  @NotBlank
  private String challengeType;
}