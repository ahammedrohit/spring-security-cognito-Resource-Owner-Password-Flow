package spring.security.cognito.application.user;

import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordResult;
import com.amazonaws.services.cognitoidp.model.UserType;
import spring.security.cognito.presentation.auth.UserSignUpRequest;

import java.util.Optional;

public interface CognitoUserService {

  UserType signUp(UserSignUpRequest signUpRequest);

  AdminSetUserPasswordResult setUserPassword(String username, String password);

  Optional<AdminInitiateAuthResult> initiateAuth(String username, String password);

  Optional<AdminRespondToAuthChallengeResult> respondToAuthChallenge(
          String username, String newPassword, String session);
}
