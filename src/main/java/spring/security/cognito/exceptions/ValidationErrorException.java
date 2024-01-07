package spring.security.cognito.exceptions;

import lombok.Getter;
import org.springframework.validation.Errors;

@Getter
public class ValidationErrorException extends RuntimeException {

  private final Errors errors;

  public ValidationErrorException(Errors errors) {
    super();
    this.errors = errors;
  }

}
