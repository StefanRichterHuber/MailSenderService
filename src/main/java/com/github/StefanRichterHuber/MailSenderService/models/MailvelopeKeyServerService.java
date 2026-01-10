package com.github.StefanRichterHuber.MailSenderService.models;

import org.jboss.resteasy.reactive.RestResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

/**
 * Interface for the Mailvelope key server service.
 * 
 * @see https://github.com/mailvelope/keyserver
 */
public interface MailvelopeKeyServerService {

    /**
     * Searches for a public key by email address on the Mailvelope key server.
     * 
     * @param email
     * @return
     */
    @Path("/api/v1/key")
    @GET
    RestResponse<MailvelopeKeySearchResponse> searchKeyByEmail(@QueryParam("email") String email);

    /**
     * Searches for a public key by key id on the Mailvelope key server.
     * 
     * @param keyId
     * @return
     */
    @Path("/api/v1/key")
    @GET
    RestResponse<MailvelopeKeySearchResponse> searchKeyByKeyId(@QueryParam("keyId") String keyId);

    /**
     * Searches for a public key by fingerprint on the Mailvelope key server.
     */
    @Path("/api/v1/key")
    @GET
    RestResponse<MailvelopeKeySearchResponse> searchKeyByFingerprint(@QueryParam("fingerprint") String fingerprint);

    /**
     * Uploads a public key to the Mailvelope key server.
     */
    @Path("/api/v1/key")
    @POST
    RestResponse<MailvelopeKeySearchResponse> uploadKey(PublicKeyUploadRequest publicKeyUploadRequest);

}
