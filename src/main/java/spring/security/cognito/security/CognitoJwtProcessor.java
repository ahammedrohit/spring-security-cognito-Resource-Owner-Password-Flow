package spring.security.cognito.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import spring.security.cognito.config.aws.AwsConfig;
import spring.security.cognito.config.token.BearerTokenWrapper;
import spring.security.cognito.exceptions.FailedAuthenticationException;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CognitoJwtProcessor {

  private final AwsConfig awsConfig;

  private final BearerTokenWrapper bearerTokenWrapper;

  public CognitoJwtProcessor(AwsConfig awsConfig, BearerTokenWrapper bearerTokenWrapper) {
    this.awsConfig = awsConfig;
    this.bearerTokenWrapper = bearerTokenWrapper;
  }

  @Bean
  public JwtAuthenticationProvider jwtAuthenticationProvider() {
    return new JwtAuthenticationProvider();
  }

  public Authentication getAuthentication(HttpServletRequest request) {
    String token = extractToken(request);

    if (token == null) {
      log.error("No Token found in HTTP Header");
      throw new FailedAuthenticationException("No Token found in HTTP Header");
    }

    try {
      RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(awsConfig.getRegion(), awsConfig.getCognito().getUserPoolId());
      Algorithm algorithm = Algorithm.RSA256(keyProvider);
      JWTVerifier jwtVerifier = JWT.require(algorithm).build();
      DecodedJWT decodedJWT = jwtVerifier.verify(token);

      if (decodedJWT.getExpiresAt().before(new Date())) {
        throw new RuntimeException("Token is expired");
      }

      if (bearerTokenWrapper.getToken() == null || !token.equals(bearerTokenWrapper.getToken())) {
        bearerTokenWrapper.setToken(token);
      }

      String username = decodedJWT.getClaims().get("username").asString();
      Collection<? extends GrantedAuthority> authorities = extractAuthorities(decodedJWT);

      User userDetails = new User(username, "", authorities);

      return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);

    } catch (Exception e) {
      log.error("Error occurred while processing Cognito Token", e);
      throw new RuntimeException(e.getMessage());
    }
  }

  private Collection<? extends GrantedAuthority> extractAuthorities(DecodedJWT decodedJWT) {
    Map<String, Claim> claims = decodedJWT.getClaims();
    Claim groupsClaim = claims.get("cognito:groups");
    if (groupsClaim != null) {
      return Arrays.stream(groupsClaim.asArray(String.class)).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
    return Collections.emptyList();
  }

  private String extractToken(HttpServletRequest request) {
    String authorizationHeader = request.getHeader("Authorization");
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      return authorizationHeader.substring(7);
    }
    return null;
  }

  private String tokenType(DecodedJWT decodedJWT) {
    return decodedJWT.getClaim("token_use").asString();
  }

}