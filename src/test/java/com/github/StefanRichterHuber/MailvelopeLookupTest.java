package com.github.StefanRichterHuber;

import java.util.Optional;

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

    @Test
    public void testLookup() {
        RestResponse<MailvelopeKeySearchResponse> response = mailvelopeKeyServerService
                .searchKeyByEmail("stefan@richter-huber.de");
        System.out.println(response.getEntity());

    }

    @Test
    public void testLookup2() {
        RestResponse<String> response = openPGPKeysServerService.getByEmail("stefan@richter-huber.de");
        System.out.println(response.getEntity());
    }

    @Test
    public void testLookup3() {
        RestResponse<String> response = openPGPKeysServerService
                .getByFingerprint("060EC5778F870626CED6FF01165B2DF3D2D2648B");
        System.out.println(response.getEntity());
    }

    @Test
    public void testLookup4() {
        publicKeySearchServices.forEach(service -> {
            byte[] key = service.searchKeyByEmail("stefan@richter-huber.de");
            System.out.println(key);
        });
    }
}
