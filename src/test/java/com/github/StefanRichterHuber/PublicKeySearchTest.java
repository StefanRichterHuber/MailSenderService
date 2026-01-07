package com.github.StefanRichterHuber;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.keysearch.MailvelopPublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.keysearch.VerifyingKeyServerKeySearchService;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;

@QuarkusTest
public class PublicKeySearchTest {

    @Inject
    VerifyingKeyServerKeySearchService vksKeySearchService;

    @Inject
    MailvelopPublicKeySearchService mailvelopeKeySearchService;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Test
    public void testVKS() {
        final byte[] key = vksKeySearchService.searchKeyByEmail(to);
        assertNotNull(key);
    }

    @Test
    public void testMailvelope() {
        final byte[] key = mailvelopeKeySearchService.searchKeyByEmail(to);
        assertNotNull(key);
    }
}
