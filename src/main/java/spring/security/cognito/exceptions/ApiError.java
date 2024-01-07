package spring.security.cognito.exceptions;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@RequiredArgsConstructor
@AllArgsConstructor
@Builder
public class ApiError {

  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private final List<Detail> details = new ArrayList<>();

  private LocalDateTime timestamp;

  private int status;

  private String error;

  private String message;

  private String path;

  public void addDetail(String target, String message) {
    details.add(new Detail(target, message));
  }

  @Getter
  @ToString
  private static class Detail {

    private final String target;

    private final String message;

    private Detail(String target, String message) {
      this.target = target;
      this.message = message;
    }
  }
}