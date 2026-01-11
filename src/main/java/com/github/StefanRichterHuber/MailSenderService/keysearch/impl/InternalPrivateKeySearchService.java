package com.github.StefanRichterHuber.MailSenderService.keysearch.impl;

import org.jboss.logging.Logger;

import com.github.StefanRichterHuber.MailSenderService.PrivateKeyProvider;
import com.github.StefanRichterHuber.MailSenderService.keysearch.PublicKeySearchService;

import jakarta.inject.Inject;

/**
 * Uses the PrivateKeyProvider to find a public key for a given email address
 */
public class InternalPrivateKeySearchService implements PublicKeySearchService {

    @Inject
    Logger logger;

    @Inject
    PrivateKeyProvider privateKeyProvider;

    @Override
    public byte[] searchKeyByEmail(String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }
        final PrivateKeyProvider.OpenPGPKeyPair keyPair = privateKeyProvider.findByMail(email);
        if (keyPair == null) {
            logger.debugf("Public Key not found for email: %s in private key", email);
            return null;
        }
        logger.infof("Public Key found for email: %s in private key", email);
        return keyPair.publicKey();
    }

}
