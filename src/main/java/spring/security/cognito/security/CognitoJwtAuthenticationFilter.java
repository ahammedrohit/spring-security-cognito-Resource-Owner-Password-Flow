package spring.security.cognito.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.security.cognito.exceptions.ApiError;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component("jwtAuthenticationFilter")
@Slf4j
public class CognitoJwtAuthenticationFilter extends OncePerRequestFilter {

  private final CognitoJwtProcessor jwtProcessor;

  public CognitoJwtAuthenticationFilter(CognitoJwtProcessor jwtProcessor) {
    this.jwtProcessor = jwtProcessor;
  }

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain) throws ServletException, IOException {

    try {
      Authentication authentication = jwtProcessor.getAuthentication(request);
      if (authentication == null) {
        response.setStatus(HttpStatus.SC_UNAUTHORIZED);
        return;
      }
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (Exception e) {
      log.error("Error occured while processing Cognito Token", e);
      SecurityContextHolder.clearContext();

      ApiError apiError = ApiError.builder()
              .status(org.springframework.http.HttpStatus.UNAUTHORIZED.value())
              .error(org.springframework.http.HttpStatus.UNAUTHORIZED.value() + " " + org.springframework.http.HttpStatus.UNAUTHORIZED.getReasonPhrase())
              .message(e.getMessage())
              .path(request.getRequestURI())
              .build();

      response.setStatus(HttpStatus.SC_UNAUTHORIZED);
      response.getWriter().write(apiError.toString());
      response.getWriter().flush();
      response.getWriter().close();
      return;
    }
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    String path = request.getRequestURI();
    List<String> excludedPaths = Arrays.asList("/actuator/health", "/v1/login", "/v1/sign-up");
    return excludedPaths.stream().anyMatch(path::startsWith);
  }
}