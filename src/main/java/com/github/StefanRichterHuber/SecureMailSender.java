package com.github.StefanRichterHuber;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Collection;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import jakarta.activation.DataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import sop.SOP;
import sop.enums.EncryptAs;
import sop.enums.SignAs;

@ApplicationScoped
public class SecureMailSender {

    @Inject
    SMTPConfig smtpConfig;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final SOP sop = new org.pgpainless.sop.SOPImpl();

    public MimeMessage createMail(
            String from,
            String to,
            String subject,
            String body,
            boolean withEncryption,
            byte[] senderKey,
            byte[] recipientCert,
            Collection<DataSource> attachments) throws Exception {
        // --- Inputs ---

        // --- 1. Create the Inner Content (Body + Attachment) ---
        Session session = Session.getDefaultInstance(new Properties());
        MimeMultipart contentMultipart = new MimeMultipart("mixed");

        // Text Part
        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "UTF-8");
        contentMultipart.addBodyPart(textPart);

        // Binary Attachment(s) Part (PDF)
        if (attachments != null) {
            for (DataSource attachment : attachments) {
                final MimeBodyPart attachmentPart = new MimeBodyPart();
                attachmentPart.setFileName(attachment.getName());
                attachmentPart.setDataHandler(new jakarta.activation.DataHandler(attachment));
                contentMultipart.addBodyPart(attachmentPart);
            }
        }

        // This is the entity we want to sign/encrypt
        MimeBodyPart contentBodyPart = new MimeBodyPart();
        contentBodyPart.setContent(contentMultipart);
        contentBodyPart.setHeader("Content-Type", contentMultipart.getContentType());

        // --- 2. Sign the Content (PGP/MIME multipart/signed) ---
        // PGP/MIME requires canonicalization (CRLF line endings)
        byte[] contentBytes = getCanonicalBytes(contentBodyPart);

        // Generate detached signature
        byte[] signature = sop.sign()
                .key(senderKey)
                .withKeyPassword(smtpConfig.senderSecretKeyPassword())
                .mode(SignAs.binary) // PGP/MIME uses detached signatures
                .data(contentBytes)
                .toByteArrayAndResult().getBytes();

        // Create the multipart/signed structure
        MimeMultipart signedMultipart = new MimeMultipart(
                "signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256");

        signedMultipart.addBodyPart(contentBodyPart); // Part 1: Signed Data

        // Part 2: The signature
        MimeBodyPart signaturePart = new MimeBodyPart();
        signaturePart.setHeader("Content-Type", "application/pgp-signature; name=\"signature.asc\"");
        signaturePart.setHeader("Content-Disposition", "attachment; filename=\"signature.asc\"");
        signaturePart.setDataHandler(
                new jakarta.activation.DataHandler(new ByteArrayDataSource(signature, "application/pgp-signature")));
        signedMultipart.addBodyPart(signaturePart);

        // Wrap the signed multipart into a BodyPart for the next step
        MimeBodyPart signedBodyPart = new MimeBodyPart();
        signedBodyPart.setContent(signedMultipart);

        // === CRITICAL FIX START ===
        // We must explicitly set the Content-Type header.
        // Without this, the encrypted blob will lack the header, and Thunderbird
        // will treat the decrypted content as plain text.
        signedBodyPart.setHeader("Content-Type", signedMultipart.getContentType());
        // === CRITICAL FIX END ===

        // --- 3. Encrypt the Content (PGP/MIME multipart/encrypted) ---
        MimeBodyPart finalBodyPart;

        if (recipientCert != null) {
            // Encrypt the ENTIRE signed body part
            final byte[] signedBytes = getCanonicalBytes(signedBodyPart);

            final byte[] encryptedData = sop.encrypt()
                    .withCert(recipientCert)
                    .signWith(senderKey) // Optional: sign inside the encryption envelope as well
                    .withKeyPassword(smtpConfig.senderSecretKeyPassword())
                    .mode(EncryptAs.text) // MIME data is binary
                    .plaintext(signedBytes)
                    .toByteArrayAndResult().getBytes();

            // Create multipart/encrypted structure
            MimeMultipart encryptedMultipart = new MimeMultipart("encrypted; protocol=\"application/pgp-encrypted\"");

            // Part 1: Version info
            MimeBodyPart versionPart = new MimeBodyPart();
            versionPart.setHeader("Content-Type", "application/pgp-encrypted");
            versionPart.setText("Version: 1"); // Standard PGP/MIME header
            encryptedMultipart.addBodyPart(versionPart);

            // Part 2: Encrypted data
            MimeBodyPart encryptedDataPart = new MimeBodyPart();
            encryptedDataPart.setHeader("Content-Type", "application/octet-stream; name=\"encrypted.asc\"");
            encryptedDataPart.setHeader("Content-Disposition", "inline; filename=\"encrypted.asc\"");
            encryptedDataPart.setDataHandler(
                    new jakarta.activation.DataHandler(
                            new ByteArrayDataSource(encryptedData, "application/octet-stream")));
            encryptedMultipart.addBodyPart(encryptedDataPart);

            finalBodyPart = new MimeBodyPart();
            finalBodyPart.setContent(encryptedMultipart);
        } else {
            // If no recipient key, just send the signed message
            finalBodyPart = signedBodyPart;
        }

        // --- 4. Finalize Message ---
        MimeMessage message = new MimeMessage(
                session);
        message.setFrom(new InternetAddress(from));
        message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(to));
        message.setSubject(subject);

        // Set the content
        message.setContent(finalBodyPart.getContent(), finalBodyPart.getContentType());

        message.saveChanges();

        return message;
    }

    /**
     * Extracts the ASCII Armored Private Key block from a mixed key file.
     */
    public static byte[] extractPrivateKey(byte[] keyFileBytes) {
        String content = new String(keyFileBytes, StandardCharsets.UTF_8);

        // Regex to find the private key block (DOTALL mode allows . to match newlines)
        Pattern pattern = Pattern.compile(
                "(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)",
                Pattern.DOTALL);

        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            return matcher.group(1).getBytes(StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException("No PGP PRIVATE KEY BLOCK found in the provided file.");
        }
    }

    /**
     * Converts a BodyPart to canonical CRLF bytes for signing.
     */
    private static byte[] getCanonicalBytes(MimeBodyPart bodyPart) throws IOException, MessagingException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        // Use the wrapper to force CRLF during serialization
        OutputStream out = new CRLFOutputStream(buffer);
        bodyPart.writeTo(out);
        return buffer.toByteArray();
    }
}
