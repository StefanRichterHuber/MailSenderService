package com.github.StefanRichterHuber.MailSenderService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

import com.github.StefanRichterHuber.MailSenderService.config.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.models.RecipientWithCert;

import io.quarkus.cache.CacheResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.Address;

/**
 * Provides the private and public key for the configured sender email. This
 * implementation fetches a mixed key file (ascii-armored private key and public
 * key) from the configured sender secret key file and extracts the public and
 * private key
 * from it.
 */
@ApplicationScoped
public class PrivateKeyProvider {

    /**
     * Regex to find the public key block (DOTALL mode allows . to match newlines)
     * in a mixed key ascii-armored file
     */
    private static final Pattern PGP_PUBLIC_KEY_PATTERN = Pattern.compile(
            "(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)",
            Pattern.DOTALL);

    /**
     * Regex to find the private key block (DOTALL mode allows . to match newlines)
     * in a mixed key ascii-armored file
     */
    private static final Pattern PGP_PRIVATE_KEY_PATTERN = Pattern.compile(
            "(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)",
            Pattern.DOTALL);

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    Logger logger;

    /**
     * Container for the private and public key and the password to decrypt the
     * private key.
     */
    public record OpenPGPKeyPair(Address email, byte[] privateKey, byte[] publicKey, char[] password) {

        public RecipientWithCert toRecipientWithCert() {
            return new RecipientWithCert(email, publicKey);
        }
    }

    /**
     * Returns the OpenPGP key pair for the given sender email.
     * 
     * @param senderEmail The sender email
     * @return The OpenPGP key pair for the given sender email, if found
     */
    @CacheResult(cacheName = "sender-private-key-cache")
    public OpenPGPKeyPair findByMail(final Address senderEmail) {
        if (senderEmail == null) {
            return null;
        }
        if (senderEmail.toString().equals(smtpConfig.from())) {
            try {
                final byte[] senderKey = smtpConfig.senderSecretKeyFile().exists()
                        ? Files.readAllBytes(smtpConfig.senderSecretKeyFile().toPath())
                        : null;

                logger.infof("Sender private key for %s read from configured file %s", smtpConfig.from(),
                        smtpConfig.senderSecretKeyFile());

                final char[] password = smtpConfig.senderSecretKeyPassword().toCharArray();
                return new OpenPGPKeyPair(senderEmail, extractPrivateKey(senderKey),
                        extractPublicKey(senderKey),
                        password);

            } catch (IOException e) {
                logger.errorf(e, "Failed to read sender private key for %s", smtpConfig.from());
                return null;
            }
        }
        return null;
    }

    /**
     * Extracts the ASCII Armored Private Key block from a mixed key file, since
     * OpenPGPainless only supports private key only files.
     */
    private static byte[] extractPrivateKey(byte[] keyFileBytes) {
        final String content = new String(keyFileBytes, StandardCharsets.UTF_8);

        final Matcher matcher = PGP_PRIVATE_KEY_PATTERN.matcher(content);
        if (matcher.find()) {
            return matcher.group(1).getBytes(StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException("No PGP PRIVATE KEY BLOCK found in the provided file.");
        }
    }

    /**
     * Extracts the ASCII Armored Public Key block from a mixed key file, since
     * OpenPGPainless only supports public key only files.
     */
    private byte[] extractPublicKey(byte[] keyFileBytes) {
        if (keyFileBytes == null || keyFileBytes.length == 0) {
            return null;
        }
        final String content = new String(keyFileBytes, StandardCharsets.UTF_8);

        final Matcher matcher = PGP_PUBLIC_KEY_PATTERN.matcher(content);
        if (matcher.find()) {
            return matcher.group(1).getBytes(StandardCharsets.UTF_8);
        } else {
            logger.warnf("No PGP PUBLIC KEY BLOCK found in the provided file: %s", new String(keyFileBytes));
            return null;
        }
    }

}
