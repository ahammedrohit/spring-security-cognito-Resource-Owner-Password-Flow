package spring.security.cognito.presentation.auth;

import com.amazonaws.services.cognitoidp.model.UserType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.cognito.application.user.UserService;
import spring.security.cognito.presentation.ApiResponse;

@RestController
@Validated
@RequestMapping("/v1")
public class AuthController {

  private final UserService userService;

  public AuthController(UserService userService) {
    this.userService = userService;
  }


  @PostMapping("/sign-up")
  public ResponseEntity<ApiResponse> signUp(@RequestBody @Validated UserSignUpRequest signUpRequest) {
    UserType result = userService.createUser(signUpRequest);
    return new ResponseEntity<>(new ApiResponse(
            result,
            "User account created successfully", false), HttpStatus.CREATED);
  }

  @PostMapping("/login")
  public ResponseEntity<ApiResponse> login(@RequestBody @Validated UserLoginRequest loginRequest) {
    return new ResponseEntity<>(userService.authenticate(loginRequest), HttpStatus.OK);
  }

  @PutMapping("/change-password")
  public ResponseEntity<ApiResponse> changePassword(@RequestBody @Validated UserPasswordUpdateRequest userPasswordUpdateRequest) {
    AuthenticatedResponse authenticatedResponse = userService.updateUserPassword(userPasswordUpdateRequest);

    return new ResponseEntity<>(new ApiResponse(authenticatedResponse, "Update successfully", false), HttpStatus.OK);
  }
}
