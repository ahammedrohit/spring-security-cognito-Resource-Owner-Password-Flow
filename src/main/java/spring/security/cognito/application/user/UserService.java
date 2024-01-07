package spring.security.cognito.application.user;

import com.amazonaws.services.cognitoidp.model.UserType;
import spring.security.cognito.presentation.ApiResponse;
import spring.security.cognito.presentation.auth.AuthenticatedResponse;
import spring.security.cognito.presentation.auth.UserLoginRequest;
import spring.security.cognito.presentation.auth.UserPasswordUpdateRequest;
import spring.security.cognito.presentation.auth.UserSignUpRequest;

public interface UserService {

  UserType createUser(UserSignUpRequest signUpRequest);

  ApiResponse authenticate(UserLoginRequest loginRequest);

  AuthenticatedResponse updateUserPassword(UserPasswordUpdateRequest userPasswordUpdateRequest);

}
