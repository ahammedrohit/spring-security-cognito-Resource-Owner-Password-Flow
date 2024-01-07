package spring.security.cognito.exceptions;

import com.amazonaws.services.cognitoidp.model.NotAuthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {


  @ExceptionHandler({FailedAuthenticationException.class, NotAuthorizedException.class, UserNotFoundException.class, InvalidPasswordException.class})
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public ApiError unauthorizedExceptions(Exception ex, HttpServletRequest request) {
    ApiError apiError = new ApiError();
    apiError.setTimestamp(LocalDateTime.now());
    apiError.setStatus(HttpStatus.UNAUTHORIZED.value());
    apiError.setError(HttpStatus.UNAUTHORIZED.getReasonPhrase());
    apiError.setMessage(ex.getMessage());
    apiError.setPath(request.getRequestURI());
    log.error("Unauthorized : " + apiError, ex);
    return apiError;
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseBody
  public ApiError handleValidationErrorException(ValidationErrorException ex, HttpServletRequest request) {
    ApiError response = new ApiError();
    response.setTimestamp(LocalDateTime.now());
    response.setStatus(HttpStatus.BAD_REQUEST.value());
    response.setError(HttpStatus.BAD_REQUEST.getReasonPhrase());
    response.setMessage("Validation error");
    response.setPath(request.getRequestURI());

    ex.getErrors().getAllErrors().forEach(error -> {
      String target = ((FieldError) error).getField();
      String message = error.getDefaultMessage();
      response.addDetail(target, message);
    });

    log.warn("Validation Error : " + response);

    return response;
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler({ConstraintViolationException.class, UsernameExistsException.class, InvalidParameterException.class})
  public ApiError processValidationError(ConstraintViolationException ex, WebRequest request) {
    String message = ex.getMessage();
    ApiError apiError = createApiError(ex, request, message);
    log.error("Bad Request : " + apiError, ex);
    return apiError;
  }


  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ResponseBody
  public ApiError handleAllException(Exception ex, WebRequest request) {
    String message = ex.getMessage();
    ApiError apiError = createApiError(ex, request, message);
    log.error("Internal Server Error : " + apiError, ex);
    return apiError;
  }

  private ApiError createApiError(Exception ex, WebRequest request, String message) {
    ApiError apiError = new ApiError();
    apiError.setTimestamp(LocalDateTime.now());
    apiError.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
    apiError.setError(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    apiError.setMessage(message);
    if (request instanceof ServletWebRequest servletWebRequest) {
      apiError.setPath(servletWebRequest.getRequest().getRequestURI());
    }
    return apiError;
  }
}