import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthOption;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;

public class SharepointOAuthTester {
    public static void main(String[] args) {

        if (args.length == 0) {
            System.out.println("USAGE SharepointOAuthTester: sharepointWebappUrl proxyHost proxyPort proxyScheme(http or https)");
            System.exit(0);
        }

        Optional<HttpHost> proxy = Optional.empty();

        String sharepointWebApplicationUrl = args[0];
        if (args.length > 1) {
            String proxyHost = args[1];
            int proxyPort = Integer.parseInt(args[2]);
            String proxyScheme = args[3];
            proxy = Optional.of(new HttpHost(proxyHost, proxyPort, proxyScheme));
        }

        try (CloseableHttpClient client = createClient(proxy)) {
            String realmId = getRealmId(sharepointWebApplicationUrl, client);
            System.out.println("Got oauth realm ID: " + realmId);
            String oauth2Endpoint = getOauth2Endpoint(realmId, client);
            System.out.println("Got oauth2Endpoint: " + oauth2Endpoint);

            java.io.Console console = System.console();
            String clientId = new String(console.readPassword("Enter oauth client ID: "));
            String clientSecret = new String(console.readPassword("Enter oauth client Secret: "));

            BearerToken bearerToken = getBearerTokenFromOauth2Endpoint(sharepointWebApplicationUrl, oauth2Endpoint, realmId, clientId, clientSecret, client);

            System.out.println("Success.Got bearer token: " + bearerToken.getToken());
            System.out.println("Bearer token expires on (UTC): " + bearerToken.getExpiresOnUtc().toString());
        } catch (IOException e) {
            throw new RuntimeException("Could not get bearer token from client ID and client secret", e);
        }
    }

    private static CloseableHttpClient createClient(Optional<HttpHost> proxy) {
        HttpClientBuilder builder = HttpClientBuilder.create();
        if (proxy.isPresent()) {
            builder.setProxy(proxy.get());
            builder.setProxyAuthenticationStrategy(new AuthenticationStrategy() {
                @Override
                public boolean isAuthenticationRequested(HttpHost authhost, HttpResponse response, HttpContext context) {
                    return false;
                }

                @Override
                public Map<String, Header> getChallenges(HttpHost authhost, HttpResponse response, HttpContext context) throws MalformedChallengeException {
                    return new HashMap<>();
                }

                @Override
                public Queue<AuthOption> select(Map<String, Header> challenges, HttpHost authhost, HttpResponse response, HttpContext context) throws MalformedChallengeException {
                    return null;
                }

                @Override
                public void authSucceeded(HttpHost authhost, AuthScheme authScheme, HttpContext context) {

                }

                @Override
                public void authFailed(HttpHost authhost, AuthScheme authScheme, HttpContext context) {

                }
            });

        }
        return builder.build();
    }


    /**
     * Gets the sharepoint tenant realm ID from the sharepoint URL.
     * <p>
     * GET
     * Endpoint: $sharepointWebApplicationUrl/_vti_bin/client.svc
     * Header:
     * <p>
     * Authorization: Bearer
     * <p>
     * Response:
     * <p>
     * Will contain a single WWW-Authenticate header that we care about that you can parse the "realm".
     *
     * @param sharepointWebApplicationUrl The sp url.
     * @param client                      The http client.
     * @return the realm. It's just a typical GUID like ef1b4fcd-83f4-43fc-aa59-dc7c4fdd9d6e
     */
    static String getRealmId(String sharepointWebApplicationUrl,
                             CloseableHttpClient client) throws IOException {
        String endpoint = String.format("%s/_vti_bin/client.svc", sharepointWebApplicationUrl);
        HttpGet httpGet = new HttpGet(endpoint);
        httpGet.setHeader("Authorization", "Bearer");
        try (CloseableHttpResponse response = client.execute(httpGet)) {
            String responseText = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            System.out.println("Get realm ID entity response from " + endpoint + ": " + responseText);
            Header wwwAuthenticateHeader = response.getFirstHeader("WWW-Authenticate");
            if (wwwAuthenticateHeader == null) {
                System.out.println("Could not get WWW-Authenticate header. Response Headers: " + StringUtils.join(response.getAllHeaders()));
            }
            String wwwAuthHeader = wwwAuthenticateHeader.getValue();
            int beginIndex = wwwAuthHeader.indexOf("realm=") + 7;
            return wwwAuthHeader.substring(beginIndex, beginIndex + 36);
        }
    }

    /**
     * Gets the sharepoint oauth2 endpoint for the given realm.
     * <p>
     * GET
     * <p>
     * Endpoint: $sharepointWebApplicationUrl/metadata/json/1?realm=${realm}
     * <p>
     * Headers: None
     * <p>
     * From response, return the oauth location which is $.endpoints[?(@.protocol=='OAuth2')].location
     *
     * @param realmId The realm from getRealmId.
     * @param client  The http client.
     * @return oauth2 location.
     */
    static String getOauth2Endpoint(String realmId, CloseableHttpClient client) throws IOException {
        HttpGet httpGet = new HttpGet(String.format("%s/metadata/json/1?realm=%s", "https://login.windows.net", realmId));
        try (CloseableHttpResponse response = client.execute(httpGet)) {
            String json = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            System.out.println("Oauth 2 endpoint response json: " + json);
            ReadContext ctx = JsonPath.parse(json);
            List<String> locations = ctx.read("$.endpoints[?(@.protocol=='OAuth2')].location");
            return locations.get(0);
        }
    }

    /**
     * Gets the sharepoint oauth2 endpoint for the given realm.
     * <p>
     * POST
     * <p>
     * Endpoint: $oauth2Endpoint
     * <p>
     * Headers: None
     * <p>
     * Form encoded post:
     * grant_type=client_credentialsclient_id=${clientId}%40${realm}client_secret=${clientSecret}scope=00000003-0000-0ff1-ce00-000000000000%2f${hostOfSharepointUrl}%40${realm}resource=00000003-0000-0ff1-ce00-000000000000%2f${hostOfSharepointUrl}%40${realm}
     * <p>
     * Bearer token and refresh timestamp are now contained in response.
     *
     * @param sharepointWebApplicationUrl The sp url.
     * @param realmId                     The realm from getRealmId.
     * @param client                      The http client.
     * @return oauth2 location.
     */
    static BearerToken getBearerTokenFromOauth2Endpoint(String sharepointWebApplicationUrl,
                                                        String oauth2Endpoint,
                                                        String realmId,
                                                        String clientId,
                                                        String clientSecret,
                                                        CloseableHttpClient client) throws IOException {
        URI uri;
        try {
            uri = new URI(sharepointWebApplicationUrl);
        } catch (URISyntaxException e) {
            throw new RuntimeException("SharePoint web application URL is not correct", e);
        }
        HttpPost post = new HttpPost(oauth2Endpoint);
        List<NameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("grant_type", "client_credentials"));
        form.add(new BasicNameValuePair("client_id", String.format("%s@%s", clientId, realmId)));
        form.add(new BasicNameValuePair("client_secret", clientSecret));
        form.add(new BasicNameValuePair("scope", String.format("00000003-0000-0ff1-ce00-000000000000/%s@%s", uri.getHost(), realmId)));
        form.add(new BasicNameValuePair("resource", String.format("00000003-0000-0ff1-ce00-000000000000/%s@%s", uri.getHost(), realmId)));

        post.setEntity(new UrlEncodedFormEntity(form, Charset.forName("UTF-8")));

        try (CloseableHttpResponse response = client.execute(post)) {
            String json = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            System.out.println("Bearer token response json: " + json);
            DocumentContext jsonPathParser = JsonPath.parse(json);
            String accessToken = jsonPathParser.read("$.access_token");
            Long expiresOn = Long.parseLong(jsonPathParser.read("$.expires_on"));
            return new BearerToken(Instant.ofEpochSecond(expiresOn), accessToken);
        }
    }
}
