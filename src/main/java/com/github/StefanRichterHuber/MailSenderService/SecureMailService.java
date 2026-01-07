package com.github.StefanRichterHuber.MailSenderService;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Security;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

import jakarta.activation.DataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import sop.SOP;
import sop.enums.EncryptAs;
import sop.enums.SignAs;

@ApplicationScoped
public class SecureMailService {

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    Logger logger;

    @Inject
    PrivateKeyProvider privateKeyProvider;

    @Inject
    Session session;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final SOP sop = new org.pgpainless.sop.SOPImpl();

    /**
     * Sends a signed email message for the configured default sender
     * 
     * @param to            The recipient's email address.
     * @param subject       The subject of the email.
     * @param body          The body of the email.
     * @param recipientCert The recipient's public key. If null, the email will not
     *                      be encrypted.
     * @param attachments   The attachments to the email.
     * @throws Exception If an error occurs.
     */
    public void sendSignedMail(
            final InternetAddress to,
            final String subject,
            final String body,
            final boolean sign,
            final boolean encrypt,
            final boolean addAutocryptHeader,
            final Iterable<DataSource> attachments) throws Exception {

        final MimeMessage mimeMessage = createSignedMail(to, subject, body, sign, encrypt, addAutocryptHeader,
                attachments);
        Transport.send(mimeMessage);
    }

    /**
     * Creates a signed email message for the configured default sender
     * 
     * @param to          The recipient's email address.
     * @param subject     The subject of the email.
     * @param body        The body of the email.
     * @param sign        Whether to sign the email.
     * @param encrypt     Whether to encrypt the email.
     * @param attachments The attachments to the email.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createSignedMail(
            final InternetAddress to,
            final String subject,
            final String body,
            final boolean sign,
            final boolean encrypt,
            final boolean addAutocryptHeader,
            final Iterable<DataSource> attachments) throws Exception {

        final InternetAddress from = new InternetAddress(smtpConfig.from());
        final byte[] senderKey = sign ? privateKeyProvider.getPrivateKey(smtpConfig.from()) : null;
        final byte[] senderPublicKey = sign ? privateKeyProvider.getPublicKey(smtpConfig.from()) : null;
        final byte[] recipientCert = encrypt ? PublicKeySearchService.findByMail(to.toString()) : null;

        MimeMessage mimeMessage = createSignedMail(from, to, subject, body, senderKey, recipientCert, attachments,
                session);

        if (addAutocryptHeader) {
            mimeMessage = addAutocryptHeader(mimeMessage, from.toString(), senderPublicKey);
        }

        return mimeMessage;
    }

    /**
     * Creates a signed email message for the configured default sender
     * 
     * @param to            The recipient's email address.
     * @param subject       The subject of the email.
     * @param body          The body of the email.
     * @param recipientCert The recipient's public key. If null, the email will not
     *                      be encrypted.
     * @param attachments   The attachments to the email.
     * @return The secure email message.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createSignedMail(
            final InternetAddress to,
            final String subject,
            final String body,
            final byte[] recipientCert,
            final Iterable<DataSource> attachments,
            final Session session) throws Exception {

        final InternetAddress from = new InternetAddress(smtpConfig.from());
        final byte[] senderKey = privateKeyProvider.getPrivateKey(smtpConfig.from());
        return createSignedMail(from, to, subject, body, senderKey, recipientCert, attachments, session);
    }

    /**
     * Creates a signed email message. Signs the message if a sender key is
     * provided. Encrypts the message if a recipient
     * certificate is provided.
     * 
     * @param from          The sender's email address. Required.
     * @param to            The recipient's email address. Required.
     * @param subject       The subject of the email. Required.
     * @param body          The body of the email. Required.
     * @param senderKey     The sender's private key. If null, the email
     *                      will not
     *                      be signed.
     * @param recipientCert The recipient's public key. If null, the email will not
     *                      be encrypted.
     * @param attachments   The attachments to the email. Optional.
     * @return The secure email message.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createSignedMail(
            final InternetAddress from,
            final InternetAddress to,
            final String subject,
            final String body,
            final byte[] senderKey,
            final byte[] recipientCert,
            Iterable<DataSource> attachments,
            Session session) throws Exception {
        // --- Inputs ---
        // Validate inputs, one after another
        if (from == null) {
            throw new IllegalArgumentException("from must not be null");
        }
        if (to == null) {
            throw new IllegalArgumentException("to must not be null");
        }
        if (subject == null || subject.isEmpty()) {
            throw new IllegalArgumentException("subject must not be null or empty");
        }
        if (body == null || body.isEmpty()) {
            throw new IllegalArgumentException("body must not be null or empty");
        }
        final boolean protectHeaders = smtpConfig.protectHeaders() && recipientCert != null;
        if (protectHeaders) {
            logger.info("Protecting headers for messages to " + to);
        }

        // --- 1. Create the Inner Content (Body + Attachment) ---
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

        if (protectHeaders) {
            // ---------------------------------------------------------
            // PROTECTED HEADERS IMPLEMENTATION (SPEC SECTIONS 3.3, 4.1)
            // ---------------------------------------------------------
            // 1. Add headers to the Cryptographic Payload (the inner content part).
            // These will be signed, ensuring authenticity[cite: 20].
            contentBodyPart.setHeader("Subject", subject);
            contentBodyPart.setHeader("From", from.toString());
            contentBodyPart.setHeader("To", to.toString());

            // 2. Append the 'protected-headers="v1"' parameter to the Content-Type.
            // This MUST be on the root of the Cryptographic Payload[cite: 155].
            String originalContentType = contentMultipart.getContentType();
            contentBodyPart.setHeader("Content-Type", originalContentType + "; protected-headers=\"v1\"");
            // ---------------------------------------------------------
        }

        // Create a temporary message to ensure all headers and so on are properly set
        MimeMessage tmp = new MimeMessage(
                session);
        tmp.setFrom(from);
        tmp.addRecipient(MimeMessage.RecipientType.TO, to);
        tmp.setSubject(subject);

        // Set the content
        tmp.setContent(contentBodyPart.getContent(), contentBodyPart.getContentType());

        // Save changes
        tmp.saveChanges();

        if (senderKey == null) {
            logger.debugf("No sender key found for email: %s. Skipping signature.", from);
            return tmp;
        } else {
            logger.debugf("Sender key found for email: %s. Signing message.", from);
        }

        // --- 2. Sign the Content (PGP/MIME multipart/signed) ---
        // PGP/MIME requires canonicalization (CRLF line endings)
        byte[] contentBytes = getCanonicalBytes(contentBodyPart);

        // Generate detached signature
        byte[] signature = sop.sign()
                .key(extractPrivateKey(senderKey))
                .withKeyPassword(smtpConfig.senderSecretKeyPassword())
                .mode(SignAs.text) // PGP/MIME uses detached signatures
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
        signedBodyPart.setHeader("Content-Type", signedMultipart.getContentType());

        // --- 3. Encrypt the Content (PGP/MIME multipart/encrypted) ---
        MimeBodyPart finalBodyPart;

        if (recipientCert != null) {
            // Encrypt the ENTIRE signed body part
            final byte[] signedBytes = getCanonicalBytes(signedBodyPart);

            final byte[] encryptedData = sop.encrypt()
                    .withCert(recipientCert)
                    .mode(EncryptAs.text) // MIME data is binary
                    .plaintext(signedBytes)
                    .toByteArrayAndResult().getBytes();

            // Create multipart/encrypted structure
            MimeMultipart encryptedMultipart = new MimeMultipart("encrypted; protocol=\"application/pgp-encrypted\"");

            // Part 1: Version info
            MimeBodyPart versionPart = new MimeBodyPart();
            versionPart.setContent("Version: 1", "application/pgp-encrypted"); // Standard PGP/MIME header
            versionPart.setDescription("PGP/MIME version identification");
            encryptedMultipart.addBodyPart(versionPart);

            // Part 2: Encrypted data
            MimeBodyPart encryptedDataPart = new MimeBodyPart();
            encryptedDataPart.setHeader("Content-Type", "application/octet-stream; name=\"encrypted.asc\"");
            encryptedDataPart.setHeader("Content-Disposition", "inline; filename=\"encrypted.asc\"");
            encryptedDataPart.setDescription("OpenPGP encrypted message");
            encryptedDataPart.setDataHandler(
                    new jakarta.activation.DataHandler(
                            new ByteArrayDataSource(encryptedData, "application/octet-stream")));
            encryptedMultipart.addBodyPart(encryptedDataPart);

            finalBodyPart = new MimeBodyPart();
            finalBodyPart.setContent(encryptedMultipart);
        } else {
            // If no recipient key, just send the signed message
            logger.debugf("No recipient key found for email: %s. Skipping encryption.", to);
            finalBodyPart = signedBodyPart;
        }

        // --- 4. Finalize Message ---
        MimeMessage message = new MimeMessage(
                session);
        message.setFrom(from);
        message.addRecipient(MimeMessage.RecipientType.TO, to);
        if (protectHeaders) {
            // If encrypted, obscure the outer subject[cite: 159, 258].
            message.setSubject(smtpConfig.encryptedSubjectPlaceholder());
        } else {
            message.setSubject(subject);
        }

        // Set the content
        message.setContent(finalBodyPart.getContent(), finalBodyPart.getContentType());

        message.saveChanges();

        return message;
    }

    /**
     * Adds an Autocrypt header to a Jakarta Mail message.
     * 
     * @param message The message to add the header to.
     * @return The message with the header added.
     * @throws MessagingException If the header cannot be set.
     * @throws IOException        If there is an error reading the byte stream.
     */
    public MimeMessage addAutocryptHeader(final MimeMessage message)
            throws MessagingException, IOException {

        final String senderMail = smtpConfig.from();

        // Read public key from *asc file
        final byte[] senderKeyAscFormat = smtpConfig.senderSecretKeyFile().exists()
                ? Files.readAllBytes(smtpConfig.senderSecretKeyFile().toPath())
                : null;
        final byte[] senderKeyAscFormatPublicOnly = extractPublicKey(senderKeyAscFormat);

        // Clean up the key (remove headers) and decode it from asc to binary
        // First check if its is raw key or asc format
        final byte[] decodedSenderKey = decodePublicKey(senderKeyAscFormatPublicOnly);

        return addAutocryptHeader(message, senderMail, decodedSenderKey);
    }

    /**
     * Adds an Autocrypt header to a Jakarta Mail message.
     *
     * @param message        The MimeMessage to modify.
     * @param senderEmail    The email address of the sender (must match the 'From'
     *                       header).
     * @param publicKeyBytes The raw binary bytes of the OpenPGP public key (NOT
     *                       ASCII armored).
     * @throws MessagingException If the header cannot be set.
     */
    private MimeMessage addAutocryptHeader(MimeMessage message, String senderEmail, byte[] publicKeyBytes)
            throws MessagingException {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            logger.warnf("No public key provided for sender: %s. Unable to add Autocrypt header.", senderEmail);
            return message;
        }
        // 1. Encode the raw key bytes to Base64
        // The Autocrypt spec requires the keydata to be the Base64 representation of
        // the binary key (without headers like '-----BEGIN PGP PUBLIC KEY BLOCK-----')
        final String base64KeyData = Base64.getEncoder().encodeToString(publicKeyBytes);

        // 2. Construct the header value
        // Format: addr=user@example.com; prefer-encrypt=mutual; keydata=BASE64BLOB
        final String headerValue = String.format("addr=%s; prefer-encrypt=mutual; keydata=%s", senderEmail,
                base64KeyData);

        // 3. Add the header to the message
        // Jakarta Mail handles the line folding (wrapping long headers) automatically.
        message.addHeader("Autocrypt", headerValue);

        logger.debugf("Successfully added Autocrypt header to message for sender: %s", senderEmail);

        return message;
    }

    /**
     * Extracts the ASCII Armored Private Key block from a mixed key file, since
     * OpenPGPainless only supports private key only files.
     */
    private static byte[] extractPrivateKey(byte[] keyFileBytes) {
        final String content = new String(keyFileBytes, StandardCharsets.UTF_8);

        // Regex to find the private key block (DOTALL mode allows . to match newlines)
        final Pattern pattern = Pattern.compile(
                "(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)",
                Pattern.DOTALL);

        final Matcher matcher = pattern.matcher(content);
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

        // Regex to find the private key block (DOTALL mode allows . to match newlines)
        final Pattern pattern = Pattern.compile(
                "(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)",
                Pattern.DOTALL);

        final Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            return matcher.group(1).getBytes(StandardCharsets.UTF_8);
        } else {
            logger.warnf("No PGP PUBLIC KEY BLOCK found in the provided file: %s", new String(keyFileBytes));
            return null;
        }
    }

    /**
     * If this is an asc encoded key, remove the headers and return the raw key
     * 
     * @throws IOException
     */
    private static byte[] decodePublicKey(byte[] keyFileBytes) throws IOException {
        if (keyFileBytes == null || keyFileBytes.length == 0) {
            return null;
        }
        final String content = new String(keyFileBytes, StandardCharsets.UTF_8);
        if (content.trim().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
            return dearmorKey(keyFileBytes);
        } else {
            // This is already a raw key
            return keyFileBytes;
        }
    }

    /**
     * Parses an ASCII Armored OpenPGP key and extracts the raw binary data.
     * This strips the headers, footers, metadata, and CRC checksum.
     *
     * @param armoredKeyBytes The byte array containing the ASCII armored key.
     * @return The raw binary key data.
     * @throws IOException If there is an error reading the byte stream.
     */
    public static byte[] dearmorKey(byte[] armoredKeyBytes) throws IOException {
        if (armoredKeyBytes == null || armoredKeyBytes.length == 0) {
            return null;
        }
        final BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(armoredKeyBytes), StandardCharsets.US_ASCII));

        final StringBuilder base64Content = new StringBuilder();
        String line;
        boolean inBlock = false;
        boolean headersFinished = false;

        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();

            // 1. Detect Start of Block
            if (trimmed.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
                inBlock = true;
                continue;
            }

            // 2. Detect End of Block
            if (trimmed.startsWith("-----END PGP PUBLIC KEY BLOCK-----")) {
                break;
            }

            if (!inBlock)
                continue;

            // 3. Skip Metadata Headers (e.g. "Version: ...")
            // Headers are separated from the Base64 body by an empty line.
            if (!headersFinished) {
                if (trimmed.isEmpty()) {
                    headersFinished = true;
                }
                continue;
            }

            // 4. Skip CRC Checksum
            // The checksum is the last line of the body and starts with '=' (e.g., =abcd)
            if (trimmed.startsWith("=")) {
                continue;
            }

            // 5. Append Base64 Data
            base64Content.append(trimmed);
        }

        if (base64Content.length() == 0) {
            throw new IllegalArgumentException("Invalid key file: No PGP data found.");
        }

        // 6. Decode the clean Base64 string to raw bytes
        return Base64.getDecoder().decode(base64Content.toString());
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
