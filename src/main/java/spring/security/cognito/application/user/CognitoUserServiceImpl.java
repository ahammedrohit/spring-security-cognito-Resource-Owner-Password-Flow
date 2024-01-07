package spring.security.cognito.application.user;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminDeleteUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminGetUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminGetUserResult;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordRequest;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.NotAuthorizedException;
import com.amazonaws.services.cognitoidp.model.UserType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import spring.security.cognito.config.aws.AwsConfig;
import spring.security.cognito.domain.enums.CognitoAttributesEnum;
import spring.security.cognito.exceptions.FailedAuthenticationException;
import spring.security.cognito.exceptions.UserNotFoundException;
import spring.security.cognito.exceptions.InvalidPasswordException;
import spring.security.cognito.exceptions.ServiceException;
import spring.security.cognito.exceptions.UsernameExistsException;
import spring.security.cognito.presentation.auth.UserSignUpRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.amazonaws.services.cognitoidp.model.ChallengeNameType.NEW_PASSWORD_REQUIRED;

@Service
@Slf4j
public class CognitoUserServiceImpl implements CognitoUserService {

  private final AWSCognitoIdentityProvider cognitoIdentityProvider;

  private final AwsConfig awsConfig;

  public CognitoUserServiceImpl(AWSCognitoIdentityProvider cognitoIdentityProvider, AwsConfig awsConfig) {
    this.cognitoIdentityProvider = cognitoIdentityProvider;
    this.awsConfig = awsConfig;
  }

  @Override
  public UserType signUp(UserSignUpRequest signUpRequest) {

    try {
      final AdminCreateUserRequest adminCreateUserRequest = new AdminCreateUserRequest()
              .withUserPoolId(awsConfig.getCognito().getUserPoolId())
              .withUsername(signUpRequest.getEmail())
              .withUserAttributes(
                      new AttributeType().withName("name").withValue(signUpRequest.getName()),
                      new AttributeType().withName("email").withValue(signUpRequest.getEmail()),
                      new AttributeType().withName("email_verified").withValue("true")

              );

      AdminCreateUserResult createUserResult = cognitoIdentityProvider.adminCreateUser(adminCreateUserRequest);
      log.info("Created User id: {}", createUserResult.getUser().getUsername());

      setUserPassword(signUpRequest.getEmail(), signUpRequest.getPassword());

      return createUserResult.getUser();
    } catch (UsernameExistsException e) {
      throw new UsernameExistsException("User already exists");
    } catch (InvalidPasswordException e) {
      throw new InvalidPasswordException("Invalid password.");
    } catch (Exception e) {
      AdminGetUserRequest adminGetUserRequest = new AdminGetUserRequest()
              .withUserPoolId(awsConfig.getCognito().getUserPoolId())
              .withUsername(signUpRequest.getEmail());

      try {
        AdminGetUserResult adminGetUserResult = cognitoIdentityProvider.adminGetUser(adminGetUserRequest);
        String userConfirmationStatus = adminGetUserResult.getUserStatus();

        if (!userConfirmationStatus.equals("CONFIRMED")) {
          AdminDeleteUserRequest adminDeleteUserRequest = new AdminDeleteUserRequest()
                  .withUserPoolId(awsConfig.getCognito().getUserPoolId())
                  .withUsername(signUpRequest.getEmail());
          cognitoIdentityProvider.adminDeleteUser(adminDeleteUserRequest);
        }
      } catch (Exception ex) {
        log.error("Failed to delete user.", ex);
      }
      throw new FailedAuthenticationException("Failed to create user.", e);
    }
  }


  @Override
  public AdminSetUserPasswordResult setUserPassword(String username, String password) {

    try {
      // Sets the specified user's password in a user pool as an administrator. Works on any user.
      AdminSetUserPasswordRequest adminSetUserPasswordRequest = new AdminSetUserPasswordRequest()
              .withUsername(username)
              .withPassword(password)
              .withUserPoolId(awsConfig.getCognito().getUserPoolId())
              .withPermanent(true);

      return cognitoIdentityProvider.adminSetUserPassword(adminSetUserPasswordRequest);
    } catch (com.amazonaws.services.cognitoidp.model.InvalidPasswordException e) {
      throw new FailedAuthenticationException(String.format("Invalid parameter: %s", e.getErrorMessage()), e);
    }
  }

  @Override
  public Optional<AdminInitiateAuthResult> initiateAuth(String username, String password) {

    final Map<String, String> authParams = new HashMap<>();
    authParams.put(CognitoAttributesEnum.USERNAME.name(), username);
    authParams.put(CognitoAttributesEnum.PASSWORD.name(), password);
    authParams.put(CognitoAttributesEnum.SECRET_HASH.name(), calculateSecretHash(awsConfig.getCognito().getAppClientId(), awsConfig.getCognito().getAppClientSecret(), username));


    final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
            .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
            .withClientId(awsConfig.getCognito().getAppClientId())
            .withUserPoolId(awsConfig.getCognito().getUserPoolId())
            .withAuthParameters(authParams);

    return adminInitiateAuthResult(authRequest);
  }

  @Override
  public Optional<AdminRespondToAuthChallengeResult> respondToAuthChallenge(String username, String newPassword, String session) {
    AdminRespondToAuthChallengeRequest request = new AdminRespondToAuthChallengeRequest();
    request.withChallengeName(NEW_PASSWORD_REQUIRED)
            .withUserPoolId(awsConfig.getCognito().getUserPoolId())
            .withClientId(awsConfig.getCognito().getAppClientId())
            .withSession(session)
            .addChallengeResponsesEntry("userAttributes.name", "aek")
            .addChallengeResponsesEntry(CognitoAttributesEnum.USERNAME.name(), username)
            .addChallengeResponsesEntry(CognitoAttributesEnum.NEW_PASSWORD.name(), newPassword)
            .addChallengeResponsesEntry(CognitoAttributesEnum.SECRET_HASH.name(), calculateSecretHash(awsConfig.getCognito().getAppClientId(), awsConfig.getCognito().getAppClientSecret(), username));

    try {
      return Optional.of(cognitoIdentityProvider.adminRespondToAuthChallenge(request));
    } catch (NotAuthorizedException e) {
      throw new NotAuthorizedException("User not found." + e.getErrorMessage());
    } catch (com.amazonaws.services.cognitoidp.model.UserNotFoundException e) {
      throw new UserNotFoundException("User not found.", e);
    } catch (com.amazonaws.services.cognitoidp.model.InvalidPasswordException e) {
      throw new InvalidPasswordException("Invalid password.", e);
    }
  }

  private String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
    final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    SecretKeySpec signingKey = new SecretKeySpec(
            userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
            HMAC_SHA256_ALGORITHM);
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
      mac.init(signingKey);
      mac.update(userName.getBytes(StandardCharsets.UTF_8));
      byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(rawHmac);
    } catch (Exception e) {
      throw new ServiceException("Error while calculating ");
    }
  }

  private Optional<AdminInitiateAuthResult> adminInitiateAuthResult(AdminInitiateAuthRequest request) {
    try {
      return Optional.of(cognitoIdentityProvider.adminInitiateAuth(request));
    } catch (NotAuthorizedException e) {
      throw new FailedAuthenticationException(String.format("Authenticate failed: %s", e.getErrorMessage()), e);
    } catch (UserNotFoundException e) {
      String username = request.getAuthParameters().get(CognitoAttributesEnum.USERNAME.name());
      throw new UserNotFoundException(String.format("Username %s  not found.", username), e);
    }
  }
}
