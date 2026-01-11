package com.github.StefanRichterHuber.MailSenderService.keysearch;

import com.github.StefanRichterHuber.MailSenderService.PrivateKeyProvider;
import com.github.StefanRichterHuber.MailSenderService.PublicKeySearchService;

import jakarta.inject.Inject;

/**
 * Uses the PrivateKeyProvider to find a public key for a given email address
 */
public class InternalPrivateKeySearchService implements PublicKeySearchService {

    @Inject
    PrivateKeyProvider privateKeyProvider;

    @Override
    public byte[] searchKeyByEmail(String email) {
        final PrivateKeyProvider.OpenPGPKeyPair keyPair = privateKeyProvider.getByMail(email);
        if (keyPair == null) {
            return null;
        }
        return keyPair.publicKey();
    }

}
