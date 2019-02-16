package org.dvaara.wso2.identity.oauth2.scope.handler;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;

//import org.apache.http.client.fluent.Request;

public class OPAScopeHandlerTest {

    @Test
    public void validateScope() throws Exception {

    }

    @Test
    public void callOPA() throws Exception {
        String query = "{\"query\": \"data.servers[i].ports[_] = \\\"p2\\\"; data.servers[i].name = name\"}";
//        HttpResponse response =
//                Request.Post("http://localhost:8181/v1/data")
//                        .bodyString(query, ContentType.APPLICATION_JSON)
//                        .execute().returnResponse();
//        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

//        System.out.println(json);
//        Assert.assertNotNull(response.getEntity().getContent());

    }

    @Test
    public void callOPAQuery() throws Exception {
//        NameValuePair nameValuePair = new NameValuePair
//                ("q", "data.spiffe.scopes[i].id = \"spiffe://example.org/wso2-is\"  data.spiffe.scopes[i].scopes= response");\
        String spiffeID = "spiffe://example.org/front-end2";
//        String encodedSpiffeID = URLEncoder.encode(String.format("data.spiffe.scopes[i].id = \"%s\"  data.spiffe.scopes[i].scopes= response",spiffeID), "UTF-8");
//        System.out.println(encodedSpiffeID);
//        HttpResponse response = Request.Get("http://localhost:8181/v1/query?q="+encodedSpiffeID)
//                .addHeader("Content-Type",ContentType.APPLICATION_FORM_URLENCODED.toString()).execute().returnResponse();
//        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
//        JsonParser parser = new JsonParser();
//        JsonElement jsonObject = parser.parse(json);
//        JsonArray allowedScopes = ((JsonObject) jsonObject).getAsJsonArray("result").get(0).getAsJsonObject().get("response").getAsJsonArray();
//                System.out.println(allowedScopes.get(0));
//        Gson gson = new Gson();
//        String[] output = gson.fromJson(allowedScopes , String[].class);
//
//        Set<String> mySet = new HashSet<String>(Arrays.asList(output));
//
//        System.out.println(mySet.toString());

        String encodedSpiffeID = URLEncoder.encode(String.format("data.scopes[i].id = \"%s\"  data.scopes[i].scopes= response",spiffeID), "UTF-8");
        System.out.println(encodedSpiffeID);
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpGet getRequest = new HttpGet("http://192.168.1.3:8181/v1/query?q="+ encodedSpiffeID);
        HttpResponse httpResponse = httpClient.execute(getRequest);

//        HttpResponse response = Request.Get("http://localhost:8181/v1/query?q="+encodedSpiffeID)
//                .addHeader("Content-Type",ContentType.APPLICATION_FORM_URLENCODED.toString()).execute().returnResponse();
        if(httpResponse.getStatusLine().getStatusCode() == 200) {
            String json = EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8);
            JsonParser parser = new JsonParser();
            JsonElement jsonObject = parser.parse(json);
            JsonArray allowedScopes = ((JsonObject) jsonObject).getAsJsonArray("result").get(0).getAsJsonObject().get("response").getAsJsonArray();
            Gson gson = new Gson();
            String[] output = gson.fromJson(allowedScopes, String[].class);

            HashSet<String> allowedSet = new HashSet<>(Arrays.asList(output));

            System.out.println(
            (String.format("Allowed set of scopes as per OPA : %s", allowedSet.toString())));
        }

    }

    private static boolean makeCall(CloseableHttpClient httpClient, HttpPost post) {

        try {
            CloseableHttpResponse response = httpClient.execute(post);
            HttpEntity entity = response.getEntity();
            boolean isAllowed = false;
            if(response.getStatusLine().getStatusCode() == 200) {
                String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                JsonParser parser = new JsonParser();
                JsonElement jsonObject = parser.parse(json);
                System.out.println(jsonObject.toString());
                isAllowed = ((JsonObject) jsonObject).get("result").getAsJsonObject().get("allow").getAsBoolean();;

//                allowedSet = new HashSet<>(Arrays.asList(output));

//                log.info(String.format("Allowed set of scopes as per OPA : %s", allowedSet.toString()));
            } else {
                System.out.println("Error in getting decision from OPA. Returning zero scopes.");
//                allowedSet = Collections.emptySet();
            }
            return isAllowed;
        } catch (IOException var4) {
            var4.printStackTrace();
            return false;
        }
    }


    @Test
    public void introspect() throws UnsupportedEncodingException {

//        CloseableHttpClient httpClient = HttpClients.custom().useSystemProperties().setSSLHostnameVerifier(new NoopHostnameVerifier()).build();
//        HttpGet get = new HttpGet(url);
//        String response = makeCall(httpClient, get);
//        System.out.println(response);
//        System.exit(1);
        DefaultHttpClient httpClient = new DefaultHttpClient();

//        curl -v -k -u  admin:admin -H 'Content-Type: application/x-www-form-urlencoded'
//                -X POST --data 'token=f19dbc8a-1511-3501-a838-6640fc90bea2' https://localhost:9443/oauth2/introspect
        String json = "{ \"input\": { \"method\": \"GET\", \"AppOwner\": \"admin@carbon.super\", \"resource\": " +
                "\"/finance/salary\", \"spiffe-id\": \"spiffe://example.org/front-end2\", \"Resource\": " +
                "\"/finance/salary\", \"Scope\": [ \"clearance1\" ], \"host\": \"wso2is:9443\", \"ClientID\": " +
                "\"spiffeexampleorgfront_end2\", \"connection\": \"Keep-Alive\", \"content-type\": " +
                "\"application/x-www-form-urlencoded\", \"Content-Length\": \"70\", \"Iat\": \"2019-02-15 17:20:53.492\"" +
                ", \"accept-encoding\": " +
                "\"gzip,deflate\", \"user-agent\": \"Apache-HttpClient/4.5.4 (Java/1.8.0_191)\" } } ";

//        String json = "{ \"input\": { \"method\": \"GET\" } } ";
        String url = "http://192.168.0.1:8181/v1/data/httpapi/authz";

        HttpPost post = new HttpPost(url);
        StringEntity requestEntity = new StringEntity(
                json,
                "application/json",
                "UTF-8");
            post.setEntity(requestEntity);
            post.setHeader("Content-Type", "application/x-www-form-urlencoded");
            post.setHeader("Method", "POST");
//            if (data.contains("token=")) {
                post.setHeader("Resource", "/finance/salary");
//            }
            boolean response = makeCall(httpClient, post);
            System.out.println(response);

//            return response;

    }

}

