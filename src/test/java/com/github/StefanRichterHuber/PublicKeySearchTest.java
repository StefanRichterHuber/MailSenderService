package com.github.StefanRichterHuber;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.PublicKeyProvider;
import com.github.StefanRichterHuber.MailSenderService.keysearch.impl.InternalPrivateKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.keysearch.impl.MailvelopPublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.keysearch.impl.VerifyingKeyServerKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.models.RecipientWithCert;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;

@QuarkusTest
public class PublicKeySearchTest {

    @Inject
    VerifyingKeyServerKeySearchService vksKeySearchService;

    @Inject
    MailvelopPublicKeySearchService mailvelopeKeySearchService;

    @Inject
    InternalPrivateKeySearchService internPrivateKeySearchService;

    @Inject
    PublicKeyProvider publicKeyProvider;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Inject
    @ConfigProperty(name = "smtp.from")
    String to2;

    @Test
    public void testVKS() throws AddressException {
        final RecipientWithCert key = vksKeySearchService.findByMail(new InternetAddress(to));
        assertNotNull(key);
    }

    @Test
    public void testMailvelope() throws AddressException {
        final RecipientWithCert key = mailvelopeKeySearchService.findByMail(new InternetAddress(to));
        assertNotNull(key);
    }

    @Test
    public void testInternal() throws AddressException {
        final RecipientWithCert key = internPrivateKeySearchService.findByMail(new InternetAddress(to2));
        assertNotNull(key);
    }

    @Test
    public void testPublicKeyProvider() throws AddressException {
        final RecipientWithCert key1 = publicKeyProvider.findByMail(new InternetAddress(to));
        assertNotNull(key1);

        final RecipientWithCert key2 = publicKeyProvider.findByMail(new InternetAddress(to2));
        assertNotNull(key2);
    }
}
