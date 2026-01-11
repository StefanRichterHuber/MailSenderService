package com.github.StefanRichterHuber.MailSenderService;

import org.jboss.logging.Logger;

import com.github.StefanRichterHuber.MailSenderService.keysearch.PublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.models.RecipientWithCert;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;

@ApplicationScoped
public class PublicKeyProvider {

    @Inject
    Logger logger;

    @Inject
    Instance<PublicKeySearchService> publicKeySearchServices;

    /**
     * Searches for a public key by email using all available implementations.
     * Returns the raw key data.
     * 
     * @param email The email address to search for.
     * @return The raw key data, or null if no key was found.
     */
    public RecipientWithCert findByMail(final String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }

        return publicKeySearchServices.stream()
                .map(service -> service.searchKeyByEmail(email))
                .filter(v -> v != null).map(v -> {
                    try {
                        return new RecipientWithCert(new InternetAddress(email), v);
                    } catch (AddressException e) {
                        logger.errorf(e, "Failed to create InternetAddress for %s", email);
                        return null;
                    }
                })
                .filter(v -> v != null)
                .findFirst()
                .orElse(null);
    }
}
