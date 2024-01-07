package spring.security.cognito.presentation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class ApiResponse {

  private Object data;
  private String message;
  private boolean error = true;

  public ApiResponse(Object data, String message) {
    this.data = data;
    this.message = message;
  }

}