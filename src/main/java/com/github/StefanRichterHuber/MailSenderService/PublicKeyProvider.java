package com.github.StefanRichterHuber.MailSenderService;

import org.jboss.logging.Logger;

import com.github.StefanRichterHuber.MailSenderService.keysearch.PublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.models.RecipientWithCert;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.mail.Address;

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
    public RecipientWithCert findByMail(final Address email) {
        if (email == null) {
            return null;
        }

        return publicKeySearchServices.stream()
                .map(service -> service.findByMail(email))
                .filter(v -> v != null)
                .findFirst()
                .orElse(null);
    }
}
