import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Convenience wrapper for bearer tokens.
 * Wraps the expires time and provides a method to tell if the token is expired.
 */
public class BearerToken {
  private Instant expiresOn;
  private String token;

  /**
   * Create a bearer token.
   * @param expiresOn The instant that this token expires.
   * @param token The bearer token.
   */
  public BearerToken(Instant expiresOn, String token) {
    this.expiresOn = expiresOn;
    this.token = token;
  }

  public String getToken() {
    return token;
  }

  /**
   * Gets offset date time - expires on in UTC timezone.
   * @return expires on time in UTC timezone.
   */
  public OffsetDateTime getExpiresOnUtc() {
    return OffsetDateTime.ofInstant(expiresOn, ZoneOffset.UTC);
  }

  public boolean isTokenValid() {
    return OffsetDateTime.now(ZoneOffset.UTC).isBefore(getExpiresOnUtc());
  }
}
