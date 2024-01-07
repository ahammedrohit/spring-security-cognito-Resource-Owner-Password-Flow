package spring.security.cognito.application.user;

import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.UserType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import spring.security.cognito.exceptions.UserNotFoundException;
import spring.security.cognito.presentation.ApiResponse;
import spring.security.cognito.presentation.auth.AuthenticatedResponse;
import spring.security.cognito.presentation.auth.UserLoginRequest;
import spring.security.cognito.presentation.auth.UserPasswordUpdateRequest;
import spring.security.cognito.presentation.auth.UserSignUpRequest;

import static com.amazonaws.services.cognitoidp.model.ChallengeNameType.NEW_PASSWORD_REQUIRED;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

  private final CognitoUserService cognitoUserService;

  public UserServiceImpl(CognitoUserService cognitoUserService) {
    this.cognitoUserService = cognitoUserService;
  }

  @Override
  public UserType createUser(UserSignUpRequest signUpRequest) {
    return cognitoUserService.signUp(signUpRequest);
  }

  @Override
  public ApiResponse authenticate(UserLoginRequest userLoginRequest) {

    AdminInitiateAuthResult result = cognitoUserService.initiateAuth(userLoginRequest.getUsername(), userLoginRequest.getPassword())
            .orElseThrow(() -> new UserNotFoundException(String.format("Username %s  not found.", userLoginRequest.getUsername())));

    // Password change required on first login
    if (ObjectUtils.nullSafeEquals(NEW_PASSWORD_REQUIRED.name(), result.getChallengeName())) {
      return new ApiResponse(AuthenticatedChallengeDTO.builder()
              .challengeType(NEW_PASSWORD_REQUIRED.name())
              .sessionId(result.getSession())
              .username(userLoginRequest.getUsername())
              .build(), "First time login - Password change required", false);
    }

    return new ApiResponse(AuthenticatedResponse.builder()
            .accessToken(result.getAuthenticationResult().getAccessToken())
            .idToken(result.getAuthenticationResult().getIdToken())
            .refreshToken(result.getAuthenticationResult().getRefreshToken())
            .username(userLoginRequest.getUsername())
            .build(), "Login successful", false);
  }

  @Override
  public AuthenticatedResponse updateUserPassword(UserPasswordUpdateRequest userPasswordUpdateRequest) {
    AdminRespondToAuthChallengeResult result = cognitoUserService.respondToAuthChallenge(
            userPasswordUpdateRequest.getUsername(),
            userPasswordUpdateRequest.getPassword(),
            userPasswordUpdateRequest.getSessionId()
    ).get();
    return AuthenticatedResponse.builder()
            .accessToken(result.getAuthenticationResult().getAccessToken())
            .idToken(result.getAuthenticationResult().getIdToken())
            .refreshToken(result.getAuthenticationResult().getRefreshToken())
            .username(userPasswordUpdateRequest.getUsername())
            .build();
  }
}
