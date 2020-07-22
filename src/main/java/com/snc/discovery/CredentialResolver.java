package com.snc.discovery;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

/**
 * Thycotic Secret Server ServiceNow MID Server CredentialResolver
 * <p>
 * The resolver requires several parameters be added to {@code config.xml}
 * depending on the mode of usage:
 * <ol>
 * <li>The OAuth2 {@code access_token} in {@code ext.tss.oauth2.grant_file} will
 * be used when that configuration parameter is defined. If the file does not
 * contain an OAuth2 Grant in JSON format, a {@link RuntimeException} is thrown
 * <li>If {@code ext.tss.oauth2.grant_file} is not defined then either
 * {@code ext.tss.url} or {@code ext.tss.api.url} and (optionally)
 * {@code ext.tss.oauth2.url}, must be defined.
 * <li>When {@code ext.tss.url} is defined then {@code ext.tss.api.url} is set
 * by appending {@link #DEFAULT_API_URL_PATH} to {@code ext.tss.url} and
 * {@code ext.tss.oauth2.url} is set in the same manner using
 * {@link #DEFAULT_OAUTH2_URL_PATH}.
 * <li>If {@code ext.tss.url} or {@code ext.tss.oauth2.url} are defined then
 * {@code ext.tss.oauth2.username} and {@code ext.tss.oauth2.password} must
 * also be defined so that an OAuth2 Grant can be requested prior to calling
 * the API.
 * </ol>
 */
public class CredentialResolver {
    private static final Log log = LogFactory.getLog(CredentialResolver.class);

    /** The string identifier as configured on the ServiceNow instance */
    public static final String ARG_ID = "id";

    /** The string type of credential as configured on the instance */
    public static final String ARG_TYPE = "type";
    // ...one of ssh_password, ssh_private_key, snmp, windows, mssql,
    // or any other ServiceNOw credential type, so long as there is
    // an appropriate mapping in the field-mappings (see below).

    /** The path that is appended to {@code ext.tss.url} to define
     * {@code ext.tss.api.url}
     */
    public static final String DEFAULT_API_URL_PATH = "/api/v1";

    /** The default path of the MID server config.xml */
    public static final String DEFAULT_CONFIG_XML_PATH = "config.xml";

    /** The path that is appended to ext.tss.url to define
     * {@code ext.tss.oauth2.url}
     */
    public static final String DEFAULT_OAUTH2_URL_PATH = "/oauth2/token";

    /** The path that is appended to ext.tss.url to define
     * {@code ext.tss.oauth2.url}
     */
    public static final String DEFAULT_OAUTH2_TOKEN_FILE_PATH = "oauth2_grant.json";

    /** The file containing the Secret Server secret template to ServiceNow
     * Discovery Credential-type field mappings
     *
     * NOTE: it is dereferenced as a resource using the ClassLoader's
     * {@code classpath}
     */
    public static final String FIELD_MAPPINGS_JSON_PATH = "tss-credential-resolver-field-mappings.json";

    // for parsing parameters from the MID Server's {@code config.xml}
    private static final SAXReader reader = new SAXReader();

    /**
     * Create an HTTP {@code Authorization} header using the given
     * {@code access_token} from Secret Server.
     *
     * @param bearerToken an {@code access_token} that is a Bearer token
     * @return the HTTP {@code Authorization} header
     */
    private static Header createAuthorizationHeader(String access_token) {
        return new BasicHeader("Authorization", "Bearer " + access_token);
    }

    /**
     * Get an OAuth2 {@code access_token} from a file containing a Grant
     *
     * @param jsonOAuth2GrantFile
     * @return the {@code access_token}
     */
    private static String getAccessToken(File jsonOAuth2GrantFile) {
        try {
            String contents = FileUtils.readFileToString(jsonOAuth2GrantFile, Charset.defaultCharset());

            // If the file contains just the access_token itself then return it
            if (Pattern.matches("^[\\w-]+={0,2}\\s*$", contents))
                return contents;

            JsonParser parser = new JsonParser();
            JsonElement grantElement = parser.parse(contents);

            if (grantElement != null
                    && !(grantElement instanceof JsonNull)
                    && grantElement.getAsJsonObject().has("access_token")) {
                return grantElement.getAsJsonObject().get("access_token").getAsString();
            } else {
                String message = "unable to parse grant from " + jsonOAuth2GrantFile;

                log.error(message);
                throw new RuntimeException(message);
            }
        } catch (IOException e) {
            String message = "error trying to read " + jsonOAuth2GrantFile;
            log.error(message, e);
            throw new RuntimeException(message, e);
        }
    }

    /**
     * Get an OAuth2 {@code access_token} from the server using a "password"
     * {@code grant_type}
     *
     * @param httpClient
     * @param url
     * @param username
     * @param password
     * @return the {@code access_token}
     */
    private static String getAccessToken(CloseableHttpClient httpClient, String url, String username,
            String password) {
        HttpPost httpPost = new HttpPost(url);
        List<NameValuePair> form = new ArrayList<NameValuePair>();

        // Secret Server supports the OAuth2 password grant_type
        form.add(new BasicNameValuePair("grant_type", "password"));
        form.add(new BasicNameValuePair("username", username));
        form.add(new BasicNameValuePair("password", password));
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(form));
        } catch (UnsupportedEncodingException e) {
            // this code uses the default encoding so something is wrong with
            // the environment if we end up here.
            String message = "unsupported encoding for username = " + username + "; password = " + password;
            log.error(message, e);
            throw new RuntimeException(message, e);
        }

        try {
            CloseableHttpResponse response = httpClient.execute(httpPost);

            if (200 != response.getStatusLine().getStatusCode()) { // HTTP 200 OK?
                String message = "unable to get an access_token; status is " + response.getStatusLine();
                log.error(message);
                throw new RuntimeException(message);
            }

            String content = EntityUtils.toString(response.getEntity());

            response.close();

            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(content);
            JsonObject oauth2Grant = null;

            // responses from .parse should be checked for null *and* JsonNull
            if (element != null && !(element instanceof JsonNull))
                oauth2Grant = element.getAsJsonObject();

            if (oauth2Grant != null && oauth2Grant.has("access_token")) {
                String access_token = oauth2Grant.get("access_token").getAsString();

                if (access_token.length() > 34)
                    log.debug("access_token = " + access_token.substring(0, 34) + "...");
                else
                    log.debug("access_token = " + access_token);
                return access_token;
            } else {
                String message = "unable to parse access_token from response = " + content;

                log.error(message);
                throw new RuntimeException(message);
            }
        } catch (IOException e) {
            String message = "I/O error invoking HTTP POST with form " + form;

            log.error(message, e);
            throw new RuntimeException(message, e);
        }
    }

    /**
     * Parses a configuration parameter from config.xml using XPath
     *
     * @param document      the config.xml {@link org.dom4j.Document}
     * @param parameterName the parameter name
     * @return the value of the specified parameter
     */
    private static String parseParamFromConfigXml(Document document, String parameterName) {
        String xpathTemplate = "/parameters/parameter[@name='%s']/@value";
        Node node = document.selectSingleNode(String.format(xpathTemplate, parameterName));

        if (node != null)
            return node.getStringValue();
        return null;
    }

    /**
     * Creates an HTTP client that respects the
     * {@code ext.tss.allow.self_signed_certificates} configuration parameter
     *
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @return a {@link org.apache.http.client.methods.CloseableHttpClient}
     */
    private CloseableHttpClient createHttpclient()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        if (allowSelfSignedCertificates) {
            SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
                    SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(),
                    new AllowAllHostnameVerifier());
            return HttpClients.custom().setSSLSocketFactory(sslConnectionSocketFactory).build();
        } else {
            return HttpClients.createDefault();
        }
    }

    private boolean allowSelfSignedCertificates = false;
    private JsonObject fieldMappingsJson;
    private String apiUrl, oauth2GrantFilePath, oauth2Url, username, password;

    /**
     * This constructor allows for the use of non-default {@code config.xml} and
     * {@code tss-credential-resolver-field-mappings.json} files for unit testing.
     * The no-argument constructor (see below) is what the ServiceNow runtime calls.
     *
     * The constructor parses the {@code ext.tss.} parameters out of
     * {@code config.xml} and loads the field-mappings
     *
     * The {@code tss-credential-resolver-field-mappings.json} file contains
     * mappings of Thycotic Secret Server secret template fields to ServiceNow
     * credential type fields. It is used to determine which fields from the secret
     * are copied to which fields in the resulting {@link java.util.Map}.
     *
     * @param configXmlPath         the path to {@code config.xml}
     * @param fieldMappingsJsonPath the classpath-relative path to the field
     *                              mappings
     */
    public CredentialResolver(String configXmlPath, String fieldMappingsJsonPath) {
        File configXml = new File(configXmlPath);

        if (!configXml.exists()) {
            String message = configXmlPath + " does not exist";

            log.error(message);
            throw new RuntimeException(message);
        }

        // Load the config.xml and check for all the necessary settings
        try {
            Document document = reader.read(configXml);
           
            this.oauth2GrantFilePath = parseParamFromConfigXml(document, "ext.tss.oauth2.grant_file");
            // allow self-signed certificates when communicating with the server
            this.allowSelfSignedCertificates = Boolean
                    .parseBoolean(parseParamFromConfigXml(document, "ext.tss.allow.self_signed_certificates"));

            // if tss.url is defined then use it to craft the API and OAuth2
            // token endpoints URLs, otherwise, initialize them from tss.api.url
            // and tss.oauth2.url respectively.
            String url = parseParamFromConfigXml(document, "ext.tss.url");

            if (url != null) {
                // derive the API and OAuth2 URLs from a base URL with default paths
                this.apiUrl = url.replaceAll("/+$", "") + DEFAULT_API_URL_PATH;
                if (oauth2GrantFilePath == null) // no OAuth2 .grant_file so we need a URL
                    this.oauth2Url = url.replaceAll("/+$", "") + DEFAULT_OAUTH2_URL_PATH;
                log.debug("apiUrl = " + this.apiUrl + "; oauthUrl = " + this.oauth2Url);
            } else {
                // use arbitrary URLs for API and OAuth2
                this.apiUrl = parseParamFromConfigXml(document, "ext.tss.api.url");
                if (this.apiUrl != null) {
                    this.apiUrl.replaceAll("/+$", "");
                    log.debug("apiUrl = " + this.apiUrl);
                }
                this.oauth2Url = parseParamFromConfigXml(document, "ext.tss.oauth2.url");
                if (this.oauth2Url != null) {
                    this.oauth2Url.replaceAll("/+$", "");
                    log.debug("oauth2Url = " + this.oauth2Url);
                }
            }
            if (this.oauth2Url != null) {
                // if we have an OAuth2 URL then we need a username and password
                this.username = parseParamFromConfigXml(document, "ext.tss.oauth2.username");
                this.password = parseParamFromConfigXml(document, "ext.tss.oauth2.password");
                if (this.username == null || this.password == null) {
                    String message = "tss.oauth2.username and tss.oauth2.password are required but missing from "
                            + configXmlPath;
                    log.error(message);
                    throw new RuntimeException(message);
                }
            }
        } catch (DocumentException e) {
            log.error("unable to read " + configXmlPath, e);
        }

        // load and parse the field-mappings JSON
        InputStream fieldMappingsJsonInputStream = this.getClass().getClassLoader()
                .getResourceAsStream(fieldMappingsJsonPath);

        if (fieldMappingsJsonInputStream == null) {
            String message = "unable to load " + fieldMappingsJsonPath + " from ClassLoader classpath";

            log.error(message);
            throw new RuntimeException(message);
        }

        JsonParser parser = new JsonParser();
        JsonElement mappingsElement = parser.parse(new InputStreamReader(fieldMappingsJsonInputStream));

        if (mappingsElement == null || mappingsElement instanceof JsonNull) {
            String message = "unable to parse field-mappings from " + fieldMappingsJsonPath;

            log.error(message);
            throw new RuntimeException(message);

        } else {
            this.fieldMappingsJson = mappingsElement.getAsJsonObject();
        }
    }

    /**
     * This constructor is called by the ServiceNow Runtime. It delegates to the
     * {@code configXmlPath} constructor, supplying {@link #DEFAULT_CONFIG_XML_PATH}
     * and {@link #FIELD_MAPPINGS_JSON_PATH} as the arguments.
     */
    public CredentialResolver() {
        this(DEFAULT_CONFIG_XML_PATH, FIELD_MAPPINGS_JSON_PATH);
    }

    /**
     * Look up the credential by its Thycotic Secret Server secret ID and copy the
     * fields of the secret to the corresponding fields in the ServiceNow
     * credential, according to the configured field-mappings.
     *
     * @param args a {@link java.util.Map} containing the credential ID and type as
     *             defined in ServiceNow
     * @return a {@link java.util.Map} containing the required credential fields
     */
    public Map<String, Object> resolve(Map<String, Object> args) {
        Header authorizationHeader = null;
        Map<String, Object> result = new HashMap<String, Object>();
        String id = (String) args.get(ARG_ID);
        String type = (String) args.get(ARG_TYPE);

        try {
            CloseableHttpClient httpClient = createHttpclient();

            if (this.oauth2Url != null) {
                authorizationHeader = createAuthorizationHeader(
                        getAccessToken(httpClient, oauth2Url, username, password));
                log.debug("Using OAuth2 Grant from the server for Authorization header");
            } else if (this.oauth2GrantFilePath != null) {
                authorizationHeader = createAuthorizationHeader(getAccessToken(new File(oauth2GrantFilePath)));
                log.debug("Using OAuth2 Grant from the grant_file for Authorization header");
            }
            // else we're assuming an Authorization header is *not* required

            HttpGet request = new HttpGet(this.apiUrl + "/secrets/" + id);

            if (authorizationHeader != null) {
                request.addHeader(authorizationHeader);
                log.debug("adding authorizationHeader");
            }

            CloseableHttpResponse response = httpClient.execute(request);

            if (200 != response.getStatusLine().getStatusCode()) { // HTTP 200 OK?
                String message = "unable to get secret with id " + id + "; status was " + response.getStatusLine();

                log.error(message);
                throw new RuntimeException(message);
            }

            String content = EntityUtils.toString(response.getEntity());

            response.close();

            JsonParser parser = new JsonParser();
            JsonElement secretElement = parser.parse(content);

            if (secretElement == null || secretElement instanceof JsonNull) {
                String message = "null response to request for secret with id " + id;

                log.error(message);
                throw new RuntimeException(message);
            }

            JsonObject secret = secretElement.getAsJsonObject();
            JsonArray secretItems = secret.getAsJsonArray("items");
            JsonElement mappingElement = this.fieldMappingsJson.get(type);

            if (mappingElement == null || mappingElement instanceof JsonNull) {
                String message = "no field-mappings for type = " + type;

                // throw unless the '*' mapping is defined
                mappingElement = this.fieldMappingsJson.get("*");
                if (mappingElement == null || mappingElement instanceof JsonNull) {
                    log.error(message);
                    throw new RuntimeException(message);
                } else {
                    message += "; using * mapping";
                    log.debug(message);
                }
            }

            JsonObject mapping = mappingElement.getAsJsonObject();

            // loop through the fields of the secret and add the ones
            // that correspond to fields in the ServiceNow credential
            // type.
            log.debug("field-mapping for " + type + " is " + mapping);
            for (int i = 0; i < secretItems.size(); i++) {
                JsonObject item = secretItems.get(i).getAsJsonObject();
                String name = item.get("fieldName").getAsString().toLowerCase();
                String value = item.get("itemValue").getAsString();
                JsonElement fileAttachmentIdElement = item.get("fileAttachmentId");
                int fileAttachmentId = -1;

                if (!(fileAttachmentIdElement instanceof JsonNull))
                    fileAttachmentId = fileAttachmentIdElement.getAsInt();

                // the value for this item is a file attachment so we
                // download it, convert it to a String and overwrite
                // the dummy string that Secret Server returns, with
                // the result.
                // NOTE: the code is eager so it will download files that
                // ServiceNow may not need; for example an SSH public key.
                if (fileAttachmentId > 0) {
                    String slug = item.get("slug").getAsString();

                    log.debug("downloading fileAttachmentId " + fileAttachmentId + ": " + slug);
                    request = new HttpGet(this.apiUrl + "/secrets/" + id + "/fields/" + slug);
                    if (authorizationHeader != null)
                        request.addHeader(authorizationHeader);
                    response = httpClient.execute(request);
                    if (200 != response.getStatusLine().getStatusCode()) {
                        String message = "unable to get " + slug + " with id "
                                + id + " and status " + response.getStatusLine();

                        log.error(message);
                        throw new RuntimeException(message);
                    } else {
                        value = EntityUtils.toString(response.getEntity());
                        log.debug("downloaded " + value.length() + " byte " + slug);
                    }
                }

                // if this field has a mapping then store the value in result
                // using name as the key.
                if (mapping.has(name) && !(mapping.get(name) instanceof JsonNull)) {
                    String key = mapping.get(name).getAsString();

                    result.put(key, value);
                    if (value.length() > 34) // truncate value to abbreviate the log entry...
                        value = value.substring(0, 34) + "...";
                    log.debug("adding " + key + ": " + value + " to result");
                }
            }
        } catch (IOException | KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error("I/O error communicating with the server", e);
        }
        return result;
    }

    /**
     * Return the API version supported by this class.
     *
     * @return the version
     */
    public String getVersion() {
        return "1.0";
    }
}
