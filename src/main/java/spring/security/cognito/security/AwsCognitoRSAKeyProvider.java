package spring.security.cognito.security;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {

  private final URL aws_kid_store_url;
  private final JwkProvider provider;

  public AwsCognitoRSAKeyProvider(String region, String userPoolId) {
    String jwksUrl = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId);
    try {
      aws_kid_store_url = new URI(jwksUrl).toURL();
    } catch (MalformedURLException e) {
      throw new RuntimeException(String.format("Invalid URL provided, URL=%s", jwksUrl));
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    provider = new JwkProviderBuilder(aws_kid_store_url).build();
  }

  @Override
  public RSAPublicKey getPublicKeyById(String kid) {
    try {
      return (RSAPublicKey) provider.get(kid).getPublicKey();
    } catch (JwkException e) {
      throw new RuntimeException(String.format("Failed to get JWT kid=%s from aws_kid_store_url=%s", kid, aws_kid_store_url));
    }
  }

  @Override
  public RSAPrivateKey getPrivateKey() {
    return null;
  }

  @Override
  public String getPrivateKeyId() {
    return null;
  }
}
