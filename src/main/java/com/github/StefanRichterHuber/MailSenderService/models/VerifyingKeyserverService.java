package com.github.StefanRichterHuber.MailSenderService.models;

import org.jboss.resteasy.reactive.RestResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;

/**
 * Interface for the Verifying Key Server service.
 * 
 * @see https://https://keys.openpgp.org/about/api/
 * 
 */
public interface VerifyingKeyserverService {
    /**
     * Searches for a public key by email address on the Verifying Key Server.
     * 
     * @param email The email address to search for.
     * @return The public key. WebApplicationException if not found.
     */
    @Path("/vks/v1/by-email/{email}")
    @Produces("application/pgp-keys")
    @GET
    RestResponse<String> getByEmail(@PathParam("email") String email);

    /**
     * Searches for a public key by fingerprint on the Verifying Key Server.
     * 
     * @param fingerprint The fingerprint to search for.
     * @return The public key. WebApplicationException if not found.
     */
    @Path("/vks/v1/by-fingerprint/{fingerprint}")
    @GET
    @Produces("application/pgp-keys")
    RestResponse<String> getByFingerprint(@PathParam("fingerprint") String fingerprint);

    /**
     * Searches for a public key by key id on the Verifying Key Server.
     * 
     * @param keyid The key id to search for.
     * @return The public key. WebApplicationException if not found.
     */
    @Path("/vks/v1/by-keyid/{keyid}")
    @GET
    @Produces("application/pgp-keys")
    RestResponse<String> getByKeyid(@PathParam("keyid") String keyid);
}
