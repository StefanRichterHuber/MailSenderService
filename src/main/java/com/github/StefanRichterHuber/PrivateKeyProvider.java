package com.github.StefanRichterHuber;

import java.io.IOException;
import java.nio.file.Files;

import org.jboss.logging.Logger;

import io.quarkus.cache.CacheResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class PrivateKeyProvider {

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    Logger logger;

    /**
     * Returns the private key for the given sender email.
     * 
     * @param senderEmail The sender email
     * @return The private key for the given sender email, if found
     */
    @CacheResult(cacheName = "private-key-cache")
    public byte[] getPrivateKey(String senderEmail) {
        if (senderEmail == null || senderEmail.isEmpty()) {
            return null;
        }
        if (senderEmail.equals(smtpConfig.from())) {
            try {
                final byte[] senderKey = smtpConfig.senderSecretKeyFile().exists()
                        ? Files.readAllBytes(smtpConfig.senderSecretKeyFile().toPath())
                        : null;

                logger.infof("Sender private key for %s read from configured file %s", smtpConfig.from(),
                        smtpConfig.senderSecretKeyFile());
                return senderKey;
            } catch (IOException e) {
                logger.errorf(e, "Failed to read sender private key for %s", smtpConfig.from());
                return null;
            }
        }
        return null;
    }
}
