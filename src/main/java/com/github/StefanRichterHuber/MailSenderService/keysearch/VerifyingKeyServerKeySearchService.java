package com.github.StefanRichterHuber.MailSenderService.keysearch;

import java.io.IOException;
import java.net.URI;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

import com.github.StefanRichterHuber.MailSenderService.PublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.models.VerifyingKeyserverService;

import io.quarkus.cache.CacheResult;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

/**
 * A key search service that searches for a public key by email address on the
 * VKS (Verifying Key Server) compatible servers like keys.openpgp.org
 */
@ApplicationScoped
public class VerifyingKeyServerKeySearchService implements PublicKeySearchService {

    @Inject
    Logger logger;

    @Inject
    SMTPConfig smtpConfig;

    /**
     * Searches for a public key by email address on the OpenPGP Key Server.
     * 
     * @param email The email address to search for.
     * @return The public key, or null if not found.
     * @see https://keys.openpgp.org/about/api/
     */
    @Override
    @CacheResult(cacheName = "vks-public-key-cache")
    public byte[] searchKeyByEmail(String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }
        for (String vksUrl : smtpConfig.vksKeyServers()) {
            final VerifyingKeyserverService openPGPKeyServerService = QuarkusRestClientBuilder.newBuilder()
                    .baseUri(URI.create(vksUrl))
                    .build(VerifyingKeyserverService.class);
            try {
                final RestResponse<String> response = openPGPKeyServerService.getByEmail(email);
                if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
                    logger.infof("Public Key found for email: %s on %s", email, vksUrl);
                    final String armouredKey = response.getEntity();
                    return PublicKeySearchService.dearmorKey(armouredKey.getBytes());
                }
                logger.debugf("Public Key not found for email: %s on %s", email, vksUrl);
                continue;
            } catch (WebApplicationException e) {
                logger.debugf("Public Key not found for email: %s on %s", email, vksUrl);
                continue;
            } catch (IOException e) {
                logger.errorf(e, "Failed to parse public key for email: %s on %s", email, vksUrl);
                throw new RuntimeException(e);
            }
        }
        return null;
    }

}
