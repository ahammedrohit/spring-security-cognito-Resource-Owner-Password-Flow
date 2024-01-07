package spring.security.cognito.config.aws;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CognitoConfiguration {

  @Bean
  public AWSCognitoIdentityProvider cognitoClient() {
    AWSCredentialsProvider credentialsProvider = new DefaultAWSCredentialsProviderChain();
    return AWSCognitoIdentityProviderClientBuilder.standard()
            .withCredentials(credentialsProvider)
            .build();
  }
}
