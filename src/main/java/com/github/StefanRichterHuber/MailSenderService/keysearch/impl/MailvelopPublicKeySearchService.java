package com.github.StefanRichterHuber.MailSenderService.keysearch.impl;

import java.io.IOException;
import java.net.URI;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

import com.github.StefanRichterHuber.MailSenderService.config.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.keysearch.PublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.models.MailvelopeKeySearchResponse;
import com.github.StefanRichterHuber.MailSenderService.models.MailvelopeKeyServerService;

import io.quarkus.cache.CacheResult;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

/**
 * This service tries to find public keys for a mail on all Mailvelope key
 * server compatible servers
 */
@ApplicationScoped
public class MailvelopPublicKeySearchService implements PublicKeySearchService {

    @Inject
    Logger logger;

    @Inject
    SMTPConfig smtpConfig;

    @Override
    @CacheResult(cacheName = "mailvelope-public-key-cache")
    public byte[] searchKeyByEmail(String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }
        for (String mailvelopeServer : smtpConfig.mailvelopeKeyServers()) {
            final MailvelopeKeyServerService mailvelopeKeyServerService = QuarkusRestClientBuilder.newBuilder()
                    .baseUri(URI.create(mailvelopeServer))
                    .build(MailvelopeKeyServerService.class);
            try {
                final RestResponse<MailvelopeKeySearchResponse> response = mailvelopeKeyServerService
                        .searchKeyByEmail(email);
                if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
                    logger.infof("Public Key found for email: %s on %s", email, mailvelopeServer);
                    final String armouredKey = response.getEntity().publicKeyArmored();
                    return PublicKeySearchService.dearmorKey(armouredKey.getBytes());
                }
                logger.debugf("Public Key not found for email: %s on %s", email, mailvelopeServer);
                continue;
            } catch (WebApplicationException e) {
                logger.debugf("Public Key not found for email: %s on %s ", email, mailvelopeServer);
                continue;
            } catch (IOException e) {
                logger.errorf(e, "Failed to parse public key for email: %s on %s", email, mailvelopeServer);
                throw new RuntimeException(e);
            }
        }
        return null;
    }

}
