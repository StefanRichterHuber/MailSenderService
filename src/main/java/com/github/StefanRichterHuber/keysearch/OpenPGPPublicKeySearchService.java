package com.github.StefanRichterHuber.keysearch;

import java.io.IOException;
import java.util.Optional;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

import com.github.StefanRichterHuber.PublicKeySearchService;
import com.github.StefanRichterHuber.models.OpenPGPKeysServerService;

import io.quarkus.cache.CacheResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class OpenPGPPublicKeySearchService implements PublicKeySearchService {

    @Inject
    Logger logger;

    @Inject
    @RestClient
    OpenPGPKeysServerService openPGPKeyServerService;

    @Override
    @CacheResult(cacheName = "mail-public-key-cache")
    public Optional<byte[]> searchKeyByEmail(String email) {
        if (email == null || email.isEmpty()) {
            return Optional.empty();
        }
        try {
            RestResponse<String> response = openPGPKeyServerService.getByEmail(email);
            if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
                logger.infof("Public Key found for email: %s on keys.openpgp.org", email);
                final String armouredKey = response.getEntity();
                return Optional.of(PublicKeySearchService.dearmorKey(armouredKey.getBytes()));
            }
            logger.infof("Public Key not found for email: %s on keys.openpgp.org", email);
            return Optional.empty();
        } catch (WebApplicationException e) {
            logger.infof("Public Key not found for email: %s on keys.openpgp.org", email);
            return Optional.empty();
        } catch (IOException e) {
            logger.errorf(e, "Failed to parse public key for email: %s on keys.openpgp.org", email);
            throw new RuntimeException(e);
        }

    }

}
