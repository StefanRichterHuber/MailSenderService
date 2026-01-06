package com.github.StefanRichterHuber;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.resteasy.reactive.RestResponse;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.models.MailvelopeKeySearchResponse;
import com.github.StefanRichterHuber.models.MailvelopeKeyServerService;
import com.github.StefanRichterHuber.models.OpenPGPKeysServerService;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

@QuarkusTest
public class MailvelopeLookupTest {

    @RestClient
    MailvelopeKeyServerService mailvelopeKeyServerService;

    @RestClient
    OpenPGPKeysServerService openPGPKeysServerService;

    @Inject
    Instance<PublicKeySearchService> publicKeySearchServices;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Test
    public void testLookup() {
        RestResponse<MailvelopeKeySearchResponse> response = mailvelopeKeyServerService
                .searchKeyByEmail(to);
        assertTrue(response.getStatus() == 200);
        assertNotNull(response.getEntity());
        assertNotNull(response.getEntity().publicKeyArmored());
        assertTrue(response.getEntity().publicKeyArmored().contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    @Test
    public void testLookup2() {
        RestResponse<String> response = openPGPKeysServerService.getByEmail(to);
        assertTrue(response.getStatus() == 200);
        assertNotNull(response.getEntity());
        assertTrue(response.getEntity().contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

}
