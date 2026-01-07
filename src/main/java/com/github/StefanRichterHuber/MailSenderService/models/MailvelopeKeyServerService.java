package com.github.StefanRichterHuber.MailSenderService.models;

import org.jboss.resteasy.reactive.RestResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

public interface MailvelopeKeyServerService {

    @Path("/api/v1/key")
    @GET
    RestResponse<MailvelopeKeySearchResponse> searchKeyByEmail(@QueryParam("email") String email);
}
