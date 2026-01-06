package com.github.StefanRichterHuber.models;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.resteasy.reactive.RestResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

@RegisterRestClient
public interface MailvelopeKeyServerService {

    @Path("/api/v1/key")
    @GET
    RestResponse<MailvelopeKeySearchResponse> searchKeyByEmail(@QueryParam("email") String email);
}
