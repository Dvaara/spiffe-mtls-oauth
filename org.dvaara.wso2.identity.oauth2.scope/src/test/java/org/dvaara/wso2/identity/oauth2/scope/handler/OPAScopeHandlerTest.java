package org.dvaara.wso2.identity.oauth2.scope.handler;

import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class OPAScopeHandlerTest {

    @Test
    public void validateScope() throws Exception {

    }

    @Test
    public void callOPA() throws Exception {
        String query = "{\"query\": \"data.servers[i].ports[_] = \\\"p2\\\"; data.servers[i].name = name\"}";
        HttpResponse response =
                Request.Post("http://localhost:8181/v1/data")
                        .bodyString(query, ContentType.APPLICATION_JSON)
                        .execute().returnResponse();
        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        System.out.println(json);
        Assert.assertNotNull(response.getEntity().getContent());

    }

}