package com.github.StefanRichterHuber.MailSenderService.models;

import org.jboss.resteasy.reactive.RestResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;

public interface VerifyingKeyserverService {
    @Path("/vks/v1/by-email/{email}")
    @GET
    RestResponse<String> getByEmail(@PathParam("email") String email);

    @Path("/vks/v1/by-fingerprint/{fingerprint}")
    @GET
    @Produces("application/pgp-keys")
    RestResponse<String> getByFingerprint(@PathParam("fingerprint") String fingerprint);
}
