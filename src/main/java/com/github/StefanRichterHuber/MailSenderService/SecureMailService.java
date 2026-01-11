package com.github.StefanRichterHuber.MailSenderService;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

import com.github.StefanRichterHuber.MailSenderService.PrivateKeyProvider.OpenPGPKeyPair;
import com.github.StefanRichterHuber.MailSenderService.models.MailContent;
import com.github.StefanRichterHuber.MailSenderService.models.MailContent.SignatureVerificationResult;

import jakarta.activation.DataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.Message.RecipientType;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;
import jakarta.mail.util.ByteArrayDataSource;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SOP;
import sop.Verification;
import sop.enums.EncryptAs;
import sop.enums.SignAs;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;
import sop.operation.Encrypt;

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
     * @param recipients  The recipient's email addresses.
     * @param subject     The subject of the email.
     * @param body        The body of the email.
     * @param sign        Whether to sign the email.
     * @param encrypt     Whether to encrypt the email.
     * @param attachments The attachments to the email. Can be null.
     * @throws Exception If an error occurs.
     */
    public void sendMail(
            final Collection<InternetAddress> recipients,
            final String subject,
            final String body,
            final boolean sign,
            final boolean encrypt,
            final Iterable<DataSource> attachments) throws Exception {

        // Inline PGP is only supported if encryption is enabled
        final boolean inlinePGP = smtpConfig.inlinePGP() && encrypt;
        final boolean pgp = sign || encrypt;
        final boolean addAutocryptHeader = smtpConfig.autocrypt();

        logger.infof("Preparing mail to %s with subject %s. Inline PGP: %b , PGP: %b, Autocrypt: %b", recipients,
                subject,
                inlinePGP, pgp, addAutocryptHeader);

        final MimeMessage mimeMessage = pgp
                ? createPGPMail(recipients, subject, body, sign, encrypt, addAutocryptHeader,
                        inlinePGP, attachments)
                : createPlainMail(recipients, subject, body, addAutocryptHeader, attachments);
        Transport.send(mimeMessage);
    }

    /**
     * Creates an mail without signing and encryption
     * 
     * @param recipients         The recipient's email addresses.
     * @param subject            The subject of the email.
     * @param body               The body of the email.
     * @param addAutocryptHeader Whether to add an autocrypt header.
     * @param attachments        The attachments to the email. Can be null.
     * @return
     * @throws Exception
     */
    public MimeMessage createPlainMail(
            final Collection<InternetAddress> recipients,
            final String subject,
            final String body,
            final boolean addAutocryptHeader,
            final Iterable<DataSource> attachments) throws Exception {

        final InternetAddress from = new InternetAddress(smtpConfig.from());
        MimeMessage mimeMessage = this.createPGPMail(from, recipients, subject, body, null, null, attachments, session);
        if (addAutocryptHeader) {
            mimeMessage = addAutocryptHeader(mimeMessage, from.toString(), null);
        }
        return mimeMessage;
    }

    /**
     * Creates a signed email message for the configured default sender
     * 
     * @param recipients         The recipient's email addresses.
     * @param subject            The subject of the email.
     * @param body               The body of the email.
     * @param sign               Whether to sign the email.
     * @param encrypt            Whether to encrypt the email.
     * @param addAutocryptHeader Whether to add an autocrypt header.
     * @param inlinePGP          Whether to use inline PGP. (Only usable if
     *                           encryption is enabled!)
     * @param attachments        The attachments to the email. Can be null.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createPGPMail(
            final Collection<InternetAddress> recipients,
            final String subject,
            final String body,
            final boolean sign,
            final boolean encrypt,
            final boolean addAutocryptHeader,
            final boolean inlinePGP,
            final Iterable<DataSource> attachments) throws Exception {

        final InternetAddress from = new InternetAddress(smtpConfig.from());
        final OpenPGPKeyPair senderKeyPair = sign ? privateKeyProvider.getByMail(smtpConfig.from()) : null;
        final List<byte[]> recipientCert = encrypt
                ? recipients.stream().map(recipient -> PublicKeySearchService.findByMail(recipient.toString())).toList()
                : Collections.emptyList();

        MimeMessage mimeMessage = inlinePGP
                ? createInlinePGPMail(from, recipients, subject, body, senderKeyPair, recipientCert, attachments,
                        session)
                : createPGPMail(from, recipients, subject, body, senderKeyPair, recipientCert, attachments,
                        session);

        if (addAutocryptHeader) {
            mimeMessage = addAutocryptHeader(mimeMessage, from.toString(), senderKeyPair);
        }

        return mimeMessage;
    }

    /**
     * Creates an "Inline PGP" email compatible with Mailvelope. But also with
     * Thunderbird and K9.
     * Note: This format does NOT support Protected Headers or embedded(!) MIME
     * attachments. Attachments are added as detached encrypted files and need to
     * be decrypted separately from the main message.
     * 
     * @param from          The sender's email address. Required.
     * @param to            The recipient's email address. Required.
     * @param subject       The subject of the email. Required. Will not be
     *                      encrypted.
     * @param body          The body of the email. Required.
     * @param senderKeyPair The sender's private key. If null, the email
     *                      will not
     *                      be signed.
     * @param recipientCert The recipient's public key. Required.
     * @param attachments   The attachments to the email. Optional.
     * @param session       The session to use for creating the message.
     * @return The secure email message.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createInlinePGPMail(
            final InternetAddress from,
            final Collection<InternetAddress> to,
            final String subject,
            final String body,
            final OpenPGPKeyPair senderKeyPair,
            final Collection<byte[]> recipientCert,
            final Iterable<DataSource> attachments,
            final Session session) throws Exception {

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
        if (recipientCert == null) {
            throw new IllegalArgumentException("Recipient certificate is required for Inline PGP encryption");
        }
        final byte[] senderKey = senderKeyPair.privateKey();
        final String senderKeyPassword = new String(senderKeyPair.password());
        final MimeMultipart rootMultipart = new MimeMultipart("mixed");

        // 1. Sign and Encrypt the body text directly
        // Inline PGP usually implies we are encrypting the text content.
        final byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

        // Prepare encryption
        // Note: For Inline PGP, we typically want the ASCII Armored output immediately
        final Encrypt encryptBuilder = sop.encrypt();
        for (byte[] cert : recipientCert) {
            encryptBuilder.withCert(cert);
        }
        encryptBuilder.mode(EncryptAs.text);

        // If we have a sender key, sign the data *inside* the encryption envelope
        if (senderKey != null) {
            encryptBuilder.signWith(senderKey)
                    .withKeyPassword(senderKeyPassword);
        }

        // Generate the ASCII Armored Block
        final byte[] encryptedBytes = encryptBuilder
                .plaintext(bodyBytes)
                .toByteArrayAndResult()
                .getBytes();

        final String encryptedAscii = new String(encryptedBytes, StandardCharsets.UTF_8);

        // 2. Create the Multipart/Alternative structure
        // This allows clients to see the block in plain text or HTML
        final MimeMultipart contentMultipart = new MimeMultipart("alternative");

        // Part A: Plain Text (The raw PGP block)
        final MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(encryptedAscii, "UTF-8");
        contentMultipart.addBodyPart(textPart);

        // Part B: HTML (The PGP block wrapped in <pre>)
        // This ensures webmails display the block cleanly for Mailvelope to detect
        final MimeBodyPart htmlPart = new MimeBodyPart();
        final String htmlContent = "<html><body><pre>" + encryptedAscii + "</pre></body></html>";
        htmlPart.setContent(htmlContent, "text/html; charset=UTF-8");
        contentMultipart.addBodyPart(htmlPart);

        MimeBodyPart mainBodyPart = new MimeBodyPart();
        mainBodyPart.setContent(contentMultipart);
        rootMultipart.addBodyPart(mainBodyPart);

        // --- 3. Process and Add Attachments. Attachments are added as detached
        // encrypted files and need to be decrypted separately from the main message ---
        if (attachments != null) {
            for (DataSource attachment : attachments) {
                // Encrypt the attachment file individually
                // We use binary mode for attachments usually, but .asc (text mode)
                // is safer for email transport to avoid corruption.
                final Encrypt fileEncryptBuilder = sop.encrypt();

                for (byte[] cert : recipientCert) {
                    fileEncryptBuilder.withCert(cert);
                }

                if (senderKey != null) {
                    fileEncryptBuilder.signWith(senderKey)
                            .withKeyPassword(senderKeyPassword);
                }

                final byte[] encryptedAttachBytes = fileEncryptBuilder.mode(EncryptAs.binary)
                        .plaintext(attachment.getInputStream())
                        .toByteArrayAndResult()
                        .getBytes();

                // Create the attachment part
                final MimeBodyPart attachPart = new MimeBodyPart();

                // Construct the data source
                final ByteArrayDataSource encryptedDs = new ByteArrayDataSource(
                        encryptedAttachBytes,
                        "application/octet-stream");

                // Set the filename - typically append .asc or .gpg
                // WARNING: The original filename is visible here.
                // If the name is sensitive, change it to "attachment1.pdf.asc"
                String fileName = attachment.getName() + ".asc";

                attachPart.setDataHandler(new jakarta.activation.DataHandler(encryptedDs));
                attachPart.setFileName(fileName);
                attachPart.setHeader("Content-Type", "application/octet-stream; name=\"" + fileName + "\"");
                attachPart.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");

                rootMultipart.addBodyPart(attachPart);
            }
        }

        // 3. Finalize Message
        final MimeMessage message = new MimeMessage(session);
        message.setFrom(from);

        for (InternetAddress recipient : to) {
            message.addRecipient(MimeMessage.RecipientType.TO, recipient);
        }

        message.setSubject(subject); // Note: Subject is NOT hidden in Inline PGP
        message.setContent(rootMultipart);
        message.saveChanges();

        return message;
    }

    /**
     * Creates a signed email message. Signs the message if a sender key is
     * provided. Encrypts the message if a recipient
     * certificate is provided. Works perfectly with K9 and Thunderbird but
     * Mailvelope does not support it.
     * 
     * @param from          The sender's email address. Required.
     * @param recipients    The recipient's email address. Required.
     * @param subject       The subject of the email. Required.
     * @param body          The body of the email. Required.
     * @param senderKeyPair The sender's private key. If null, the email
     *                      will not
     *                      be signed.
     * @param recipientCert The recipient's public key. If null, the email will not
     *                      be encrypted.
     * @param attachments   The attachments to the email. Optional.
     * @return The secure email message.
     * @throws Exception If an error occurs.
     */
    public MimeMessage createPGPMail(
            final InternetAddress from,
            final Collection<InternetAddress> recipients,
            final String subject,
            final String body,
            final OpenPGPKeyPair senderKeyPair,
            final Collection<byte[]> recipientCert,
            final Iterable<DataSource> attachments,
            Session session) throws Exception {
        // --- Inputs ---
        // Validate inputs, one after another
        if (from == null) {
            throw new IllegalArgumentException("from must not be null");
        }
        if (recipients == null) {
            throw new IllegalArgumentException("recipients must not be null");
        }
        if (subject == null || subject.isEmpty()) {
            throw new IllegalArgumentException("subject must not be null or empty");
        }
        if (body == null || body.isEmpty()) {
            throw new IllegalArgumentException("body must not be null or empty");
        }
        final boolean protectHeaders = smtpConfig.protectHeaders() && recipientCert != null;
        if (protectHeaders) {
            logger.debugf("Protecting headers for messages to %s", recipients);
        }
        final byte[] senderKey = senderKeyPair.privateKey();
        final String senderKeyPassword = new String(senderKeyPair.password());

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
            contentBodyPart.setHeader("To",
                    recipients.stream().map(InternetAddress::toString).collect(Collectors.joining(", ")));

            // 2. Append the 'protected-headers="v1"' parameter to the Content-Type.
            // This MUST be on the root of the Cryptographic Payload[cite: 155].
            String originalContentType = contentMultipart.getContentType();
            contentBodyPart.setHeader("Content-Type", originalContentType + "; protected-headers=\"v1\"");
            // ---------------------------------------------------------
        }

        // Create a temporary message to ensure all headers and so on are properly set

        // Set the content (some headers are only properly set in a MimeBodyPart if the
        // part is added to a MimeMessage and MimeMessage.saveChanges() is called)
        final MimeMessage tmp = new MimeMessage(session);
        tmp.setFrom(from);
        for (InternetAddress recipientTo : recipients) {
            tmp.addRecipient(MimeMessage.RecipientType.TO, recipientTo);
        }
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
        final byte[] contentBytes = getCanonicalBytes(contentBodyPart);

        // Generate detached signature
        final byte[] signature = sop.sign()
                .key(senderKey)
                .withKeyPassword(senderKeyPassword)
                .mode(SignAs.text) // PGP/MIME uses detached signatures
                .data(contentBytes)
                .toByteArrayAndResult().getBytes();

        // Create the multipart/signed structure
        final MimeMultipart signedMultipart = new MimeMultipart(
                "signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256");

        signedMultipart.addBodyPart(contentBodyPart); // Part 1: Signed Data

        // Part 2: The signature
        final MimeBodyPart signaturePart = new MimeBodyPart();
        signaturePart.setDataHandler(
                new jakarta.activation.DataHandler(new ByteArrayDataSource(signature, "application/pgp-signature")));
        signaturePart.setFileName("signature.asc");
        signedMultipart.addBodyPart(signaturePart);

        // Wrap the signed multipart into a BodyPart for the next step
        final MimeBodyPart signedBodyPart = new MimeBodyPart();
        signedBodyPart.setContent(signedMultipart);
        signedBodyPart.setHeader("Content-Type", signedMultipart.getContentType());

        // Set the content (some headers are only properly set in a MimeBodyPart if the
        // part is added to a MimeMessage and MimeMessage.saveChanges() is called)
        tmp.setContent(signedBodyPart.getContent(), signedBodyPart.getContentType());

        // Save changes
        tmp.saveChanges();

        // --- 3. Encrypt the Content (PGP/MIME multipart/encrypted) ---
        final MimeBodyPart finalBodyPart;

        if (recipientCert != null) {
            // Encrypt the ENTIRE signed body part
            final byte[] signedBytes = getCanonicalBytes(signedBodyPart);

            // final byte[] encryptedData = sop.encrypt()
            // .withCert(recipientCert)
            // .mode(EncryptAs.text) // MIME data is binary
            // .plaintext(signedBytes)
            // .toByteArrayAndResult().getBytes();

            Encrypt encrypt = sop.encrypt();
            for (byte[] cert : recipientCert) {
                encrypt = encrypt.withCert(cert);
            }
            final byte[] encryptedData = encrypt.mode(EncryptAs.text) // MIME data is binary
                    .plaintext(signedBytes)
                    .toByteArrayAndResult().getBytes();

            // Create multipart/encrypted structure
            final MimeMultipart encryptedMultipart = new MimeMultipart(
                    "encrypted; protocol=\"application/pgp-encrypted\"");

            // Part 1: Version info
            final MimeBodyPart versionPart = new MimeBodyPart();
            versionPart.setContent("Version: 1", "application/pgp-encrypted"); // Standard PGP/MIME header
            versionPart.setDescription("PGP/MIME version identification");
            encryptedMultipart.addBodyPart(versionPart);

            // Part 2: Encrypted data
            final MimeBodyPart encryptedDataPart = new MimeBodyPart();
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
            logger.debugf("No recipient key found for email: %s. Skipping encryption.", recipients);
            finalBodyPart = signedBodyPart;
        }

        // --- 4. Finalize Message ---
        MimeMessage message = new MimeMessage(
                session);
        message.setFrom(from);
        for (InternetAddress recipient : recipients) {
            message.addRecipient(MimeMessage.RecipientType.TO, recipient);
        }
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

        final OpenPGPKeyPair senderKeyPair = privateKeyProvider.getByMail(smtpConfig.from());
        return addAutocryptHeader(message, smtpConfig.from(), senderKeyPair);
    }

    /**
     * Adds an Autocrypt header to a Jakarta Mail message.
     *
     * @param message     The MimeMessage to modify.
     * @param senderEmail The email address of the sender (must match the 'From'
     *                    header).
     * @param keyPair     The OpenPGP key pair (private and public key).
     * @throws MessagingException If the header cannot be set.
     * @throws IOException
     */
    private MimeMessage addAutocryptHeader(final MimeMessage message, final String senderEmail,
            final OpenPGPKeyPair keyPair)
            throws MessagingException, IOException {
        if (keyPair == null || keyPair.publicKey() == null || keyPair.publicKey().length == 0) {
            logger.warnf("No public key provided for sender: %s. Unable to add Autocrypt header.", senderEmail);
            return message;
        }
        final byte[] publicKeyBytes = decodePublicKey(keyPair.publicKey());

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
     * Parses a mime message. If parts / the whole message is encrypted, it will be
     * decrypted and signed parts will be verified. Supports plain text and HTML
     * content, simple pgp and pgp/mime encrypted content.
     * 
     * @param mimeMessage The mime message to parse
     * @return The parsed mail content
     * @throws MessagingException
     * @throws IOException
     */
    public MailContent decodeMimeMessage(MimeMessage mimeMessage)
            throws MessagingException, IOException {

        if (mimeMessage == null) {
            throw new IllegalArgumentException("MimeMessage must not be null");
        }

        final String from = mimeMessage.getFrom()[0].toString();
        final String to = mimeMessage.getRecipients(RecipientType.TO)[0].toString();
        final OpenPGPKeyPair receiverKeyPair = privateKeyProvider.getByMail(to);
        final byte[] senderPublicKey = PublicKeySearchService.findByMail(from);
        return decodeMimeMessage(mimeMessage, receiverKeyPair, senderPublicKey);
    }

    /**
     * Parses a mime message. If parts / the whole message is encrypted, it will be
     * decrypted and signed parts will be verified. Supports plain text and HTML
     * content, simple pgp and pgp/mime encrypted content.
     * 
     * @param mimeMessage     The mime message to parse
     * @param receiverKeyPair The key pair of the receiver (private key), if null,
     *                        the message will not be decrypted
     * @param senderPublicKey The public key of the sender (public key), if null,
     *                        the message will not be verified
     * @return The parsed mail content
     * @throws MessagingException
     * @throws IOException
     */
    public MailContent decodeMimeMessage(MimeMessage mimeMessage, OpenPGPKeyPair receiverKeyPair,
            byte[] senderPublicKey)
            throws MessagingException, IOException {

        if (mimeMessage == null) {
            throw new IllegalArgumentException("MimeMessage must not be null");
        }

        // First check if this is PGP/MIME (multipart/encrypted) encrypted mail
        if (mimeMessage.isMimeType("multipart/encrypted")) {
            return decodeEncryptedMimeMessage(mimeMessage, receiverKeyPair, senderPublicKey);
        }

        final MailContent mailContent = parseMimePart(mimeMessage, receiverKeyPair, senderPublicKey);
        // Check if the mail content contained a (encrypted) subject and from field, if
        // not take the one from the mime message
        final String from = mailContent.from() != null ? mailContent.from() : mimeMessage.getFrom()[0].toString();
        final String subject = mailContent.subject() != null ? mailContent.subject() : mimeMessage.getSubject();
        final String to = mailContent.to() != null ? mailContent.to()
                : mimeMessage.getRecipients(RecipientType.TO)[0].toString();
        return new MailContent(from, to, subject, mailContent.bodies(), mailContent.attachments(),
                mailContent.signatureVerified());

    }

    /**
     * Parses a mime message that is encrypted with PGP/MIME (multipart/encrypted)
     * 
     * @param mimeMessage     The mime message to parse
     * @param receiverKeyPair The key pair of the receiver (private key), if null,
     *                        the message will not be decrypted
     * @param senderPublicKey The public key of the sender (public key), if null,
     *                        the message will not be verified
     * @return The parsed mail content
     * @throws IOException
     * @throws MessagingException
     */
    private MailContent decodeEncryptedMimeMessage(MimeMessage mimeMessage, OpenPGPKeyPair receiverKeyPair,
            byte[] senderPublicKey) throws IOException, MessagingException {
        final MimeMultipart mimeMultipart = (MimeMultipart) mimeMessage.getContent();
        // First message part is version imformation and of content type
        // application/pgp-encrypted
        final MimeBodyPart versionPart = (MimeBodyPart) mimeMultipart.getBodyPart(0);
        if (!versionPart.isMimeType("application/pgp-encrypted")) {
            throw new IllegalArgumentException(
                    "Mail is not pgp/mime encrypted - wrong content type ('application/pgp-encrypted' expected): "
                            + versionPart.getContentType());
        }
        if (!versionPart.getContent().equals("Version: 1")) {
            throw new IllegalArgumentException(
                    "Mail is not pgp/mime encrypted - wrong version ('Version: 1' expected): "
                            + versionPart.getContent());
        }
        // Second message part is encrypted content. Content type is
        // application/octet-stream
        final MimeBodyPart encryptedPart = (MimeBodyPart) mimeMultipart.getBodyPart(1);
        if (!encryptedPart.isMimeType("application/octet-stream")) {
            throw new IllegalArgumentException(
                    "Mail is not pgp/mime encrypted - wrong content type ('application/octet-stream' expected): "
                            + encryptedPart.getContentType());
        }

        final byte[] encryptedContent = getBytesFromMimePart(encryptedPart);
        final ConditionalDecryptionResult decryptedResult = this.decryptIfEncrypted(encryptedContent, receiverKeyPair,
                senderPublicKey);
        final byte[] decryptedContent = decryptedResult.content();
        final MimeMessage decryptedMimeMessage = new MimeMessage(mimeMessage.getSession(),
                new ByteArrayInputStream(decryptedContent));

        /*
         * Copy all headers from the original mime message to the decrypted mime message
         */
        if (mimeMessage.getFrom() != null && mimeMessage.getFrom().length > 0) {
            for (int i = 0; i < mimeMessage.getFrom().length; i++) {
                decryptedMimeMessage.setFrom(mimeMessage.getFrom()[i]);
            }
        }
        if (mimeMessage.getSubject() != null) {
            decryptedMimeMessage.setSubject(mimeMessage.getSubject());
        }
        if (mimeMessage.getRecipients(RecipientType.TO) != null
                && mimeMessage.getRecipients(RecipientType.TO).length > 0) {
            decryptedMimeMessage.setRecipients(RecipientType.TO, mimeMessage.getRecipients(RecipientType.TO));
        }
        if (mimeMessage.getRecipients(RecipientType.CC) != null
                && mimeMessage.getRecipients(RecipientType.CC).length > 0) {
            decryptedMimeMessage.setRecipients(RecipientType.CC, mimeMessage.getRecipients(RecipientType.CC));
        }
        if (mimeMessage.getRecipients(RecipientType.BCC) != null
                && mimeMessage.getRecipients(RecipientType.BCC).length > 0) {
            decryptedMimeMessage.setRecipients(RecipientType.BCC, mimeMessage.getRecipients(RecipientType.BCC));
        }

        final MailContent c = new MailContent(null, null, null, null, null, decryptedResult.signatureVerified());
        return mergeMailContents(List.of(c, decodeMimeMessage(decryptedMimeMessage, receiverKeyPair, senderPublicKey)));
    }

    /**
     * Recursively parses the given mime part and returns the mail content.
     * 
     * @param mimePart        The mime part to parse
     * @param receiverKeyPair The receiver's key pair
     * @param senderPublicKey The sender's public key
     * @return The mail content
     * @throws MessagingException if an error occurs while parsing the mime part
     * @throws IOException        if an I/O error occurs
     */
    private MailContent parseMimePart(MimePart mimePart, OpenPGPKeyPair receiverKeyPair, byte[] senderPublicKey)
            throws MessagingException, IOException {
        if (mimePart.isMimeType("multipart/signed")) {
            // This is a signed but not encrypted content block

            final MimeMultipart mimeMultipart = (MimeMultipart) mimePart.getContent();
            MimeBodyPart signaturePart = null;
            MimeBodyPart signedPart = null;

            if (mimeMultipart.getCount() != 2) {
                throw new IllegalArgumentException("Multipart signed content block must have exactly 2 parts");
            }

            for (int i = 0; i < mimeMultipart.getCount(); i++) {
                final MimeBodyPart mimeBodyPart = (MimeBodyPart) mimeMultipart.getBodyPart(i);
                if (mimeBodyPart.isMimeType("application/pgp-signature")
                        || Objects.equals(mimeBodyPart.getFileName(), "signature.asc")) {
                    signaturePart = mimeBodyPart;
                } else {
                    signedPart = mimeBodyPart;
                }
            }
            if (signaturePart == null) {
                throw new IllegalArgumentException("Signature part is missing");
            }
            if (signedPart == null) {
                throw new IllegalArgumentException("Signed part is missing");
            }

            final boolean signatureVerified = verifySignature(signedPart, signaturePart, senderPublicKey);
            final MailContent mc = new MailContent(null, null, null, null, null,
                    signatureVerified ? MailContent.SignatureVerificationResult.SignatureVerified
                            : MailContent.SignatureVerificationResult.SignatureInvalid);

            return this.mergeMailContents(List.of(mc, parseMimePart(signedPart, receiverKeyPair, senderPublicKey)));
        } else if (mimePart.isMimeType("multipart/*")) {
            final List<MailContent> mailContents = new ArrayList<>();
            if (mimePart.getContentType().contains("protected-headers=\"v1\"")) {
                logger.debugf("Mime part contains protected headers v1");
                // Check if this part has from / to / subject fields -> this happens when the
                // mail is pgp/mime encrypted
                final String from = Optional.ofNullable(mimePart.getHeader("From")).filter(s -> s.length > 0)
                        .map(s -> s[0]).orElse(null);
                final String subject = Optional.ofNullable(mimePart.getHeader("Subject")).filter(s -> s.length > 0)
                        .map(s -> s[0]).orElse(null);
                final String to = Optional.ofNullable(mimePart.getHeader("To")).filter(s -> s.length > 0)
                        .map(s -> s[0]).orElse(null);
                mailContents.add(new MailContent(from, to, subject, new ArrayList<>(), new ArrayList<>(),
                        MailContent.SignatureVerificationResult.NoSignature));
            }

            // Recursivle parse all parts
            if (mimePart.getContent() instanceof MimeMultipart) {
                final MimeMultipart mimeMultipart = (MimeMultipart) mimePart.getContent();

                for (int i = 0; i < mimeMultipart.getCount(); i++) {
                    final MailContent mailContent = parseMimePart((MimeBodyPart) mimeMultipart.getBodyPart(i),
                            receiverKeyPair, senderPublicKey);
                    mailContents.add(mailContent);
                }
                return mergeMailContents(mailContents);
            }
        } else if (mimePart.isMimeType("text/plain") || mimePart.isMimeType("text/html")) {
            final byte[] content = getBytesFromMimePart(mimePart);
            final ConditionalDecryptionResult decryptedResult = decryptIfEncrypted(content, receiverKeyPair,
                    senderPublicKey);
            final String decryptedContent = new String(decryptedResult.content(), StandardCharsets.UTF_8);

            final MimeBodyPart mimeBodyPart = new MimeBodyPart();
            mimeBodyPart.setContent(decryptedContent, mimePart.getContentType());
            if (mimePart.getFileName() != null)
                mimeBodyPart.setFileName(mimePart.getFileName());
            if (mimePart.getDisposition() != null)
                mimeBodyPart.setDisposition(mimePart.getDisposition());
            if (mimePart.getDescription() != null)
                mimeBodyPart.setDescription(mimePart.getDescription());
            if (mimePart.getContentID() != null)
                mimeBodyPart.setContentID(mimePart.getContentID());
            if (mimePart.getContentLanguage() != null)
                mimeBodyPart.setContentLanguage(mimePart.getContentLanguage());
            return new MailContent(null, null, null, List.of(mimeBodyPart), null,
                    decryptedResult.signatureVerified());
        } else if (mimePart.isMimeType("application/*")) {
            final byte[] content = getBytesFromMimePart(mimePart);
            final ConditionalDecryptionResult decryptedResult = decryptIfEncrypted(content, receiverKeyPair,
                    senderPublicKey);
            final byte[] decryptedContent = decryptedResult.content();

            String fileName = mimePart.getFileName();
            if (fileName == null) {
                fileName = mimePart.getContentID();
            }
            // Clean up file name ( remove extensions like .pgp, .asc, .gpg )
            if (fileName != null
                    && (fileName.endsWith(".asc") || fileName.endsWith(".pgp") || fileName.endsWith(".gpg"))) {
                fileName = fileName.substring(0, fileName.lastIndexOf('.'));
            }

            final ByteArrayDataSource dataSource = new ByteArrayDataSource(decryptedContent, mimePart.getContentType());
            dataSource.setName(fileName);
            return new MailContent(null, null, null, null, List.of(dataSource), decryptedResult.signatureVerified());

        }
        logger.warnf("Unsupported mime type: %s", mimePart.getContentType());
        return null;
    }

    /**
     * Returns the content of the given mime part as byte array.
     * 
     * @param mimePart The mime part to get the content from
     * @return The content of the mime part as byte array
     * @throws IOException
     * @throws MessagingException
     */
    private byte[] getBytesFromMimePart(MimePart mimePart) throws IOException, MessagingException {
        if (mimePart == null || mimePart.getContent() == null) {
            return null;
        }
        if (mimePart.getContent() instanceof byte[]) {
            return (byte[]) mimePart.getContent();
        }
        if (mimePart.getContent() instanceof InputStream) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ((InputStream) mimePart.getContent()).transferTo(bos);
            return bos.toByteArray();
        }
        if (mimePart.getContent() instanceof String) {
            return ((String) mimePart.getContent()).getBytes(StandardCharsets.UTF_8);
        }
        if (mimePart.getContent() instanceof MimeMultipart) {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            mimePart.writeTo(bos);
            return bos.toByteArray();
        }
        logger.errorf("Content of mime part is of type %s and cannot be read",
                mimePart.getContent().getClass().getName());
        return null;
    }

    /**
     * Container for the decrypted content and the result of the decryption.
     */
    private record ConditionalDecryptionResult(byte[] content, boolean isEncrypted,
            SignatureVerificationResult signatureVerified) {
    }

    /**
     * Decrypts the given content if it is encrypted.
     * 
     * @param content         The content to decrypt
     * @param receiverKeyPair The receiver's key pair
     * @param senderPublicKey The sender's public key
     * @return The decrypted content
     * @throws SOPGPException if an error occurs during decryption
     * @throws IOException    if an I/O error occurs
     */
    private ConditionalDecryptionResult decryptIfEncrypted(byte[] content, OpenPGPKeyPair receiverKeyPair,
            byte[] senderPublicKey)
            throws SOPGPException, IOException {

        if (content == null || content.length == 0) {
            return new ConditionalDecryptionResult(null, false, SignatureVerificationResult.NoSignature);
        }

        if (receiverKeyPair == null) {
            logger.debug("No private key for receiver provider");
            return new ConditionalDecryptionResult(content, false, SignatureVerificationResult.NoSignature);
        }

        final Pattern pattern = Pattern.compile(
                "(-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----)",
                Pattern.DOTALL);
        final Matcher matcher = pattern.matcher(new String(content));
        if (matcher.find()) {
            boolean isSigned = false;
            final String encodedContent = matcher.group(1);

            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Decrypt decrypt = sop.decrypt()
                    .withKey(receiverKeyPair.privateKey())
                    .withKeyPassword(new String(receiverKeyPair.password()));

            if (senderPublicKey != null) {

                decrypt = decrypt.verifyWithCert(senderPublicKey);
                isSigned = true;
            } else {
                logger.warn("No public key for sender provided to verify signature");
            }

            final ReadyWithResult<DecryptionResult> result = decrypt
                    .ciphertext(encodedContent.getBytes(StandardCharsets.UTF_8));
            result.writeTo(outputStream);

            return new ConditionalDecryptionResult(outputStream.toByteArray(), true,
                    isSigned ? SignatureVerificationResult.SignatureVerified : SignatureVerificationResult.NoSignature);
        }
        return new ConditionalDecryptionResult(content, false, SignatureVerificationResult.NoSignature);
    }

    /**
     * Verifies the signature of the given content and signature.
     * 
     * @param content   the content to verify
     * @param signature the signature to verify
     * @param publicKey the public key to verify the signature with
     * @return true if the signature is valid, false otherwise
     * @throws IOException if an I/O error occurs
     */
    private boolean verifySignature(MimeBodyPart content, MimeBodyPart signature, byte[] publicKey)
            throws MessagingException, IOException {

        if (content == null) {
            logger.warn("Content is null");
            return false;
        }

        if (signature == null) {
            logger.warn("Signature is null");
            return false;
        }

        if (publicKey == null) {
            logger.warn("Public key is null");
            return false;
        }

        final byte[] contentBytes = getBytesFromMimePart(content);
        final byte[] signatureBytes = getBytesFromMimePart(signature);
        return verifySignature(contentBytes, signatureBytes, publicKey);
    }

    /**
     * Verifies the signature of the given content and signature.
     * 
     * @param content   the content to verify
     * @param signature the signature to verify
     * @param publicKey the public key to verify the signature with
     * @return true if the signature is valid, false otherwise
     * @throws IOException if an I/O error occurs
     */
    private boolean verifySignature(byte[] content, byte[] signature, byte[] publicKey) throws IOException {
        if (content == null || content.length == 0) {
            logger.warn("Content is null or empty");
            return false;
        }

        if (signature == null || signature.length == 0) {
            logger.warn("Signature is null or empty");
            return false;
        }

        if (publicKey == null || publicKey.length == 0) {
            logger.warn("Public key is null or empty");
            return false;
        }

        try {
            final List<Verification> result = sop.verify().cert(publicKey).signatures(signature).data(content);
            logger.debugf("Signature verification successful. Result: %s", result);
            return result.size() > 0;
        } catch (SOPGPException e) {
            logger.warnf("Signature verification failed: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Merges the given mail contents into a single mail content.
     * 
     * @param mailContents the mail contents to merge
     * @return the merged mail content
     */
    private MailContent mergeMailContents(Iterable<? extends MailContent> mailContents) {
        String from = null;
        String subject = null;
        String to = null;
        List<MimeBodyPart> bodies = new ArrayList<>();
        List<DataSource> attachments = new ArrayList<>();
        MailContent.SignatureVerificationResult signatureVerified = MailContent.SignatureVerificationResult.NoSignature;
        for (MailContent mailContent : mailContents) {
            if (mailContent == null) {
                continue;
            }
            if (mailContent.from() != null) {
                from = mailContent.from();
            }
            if (mailContent.to() != null) {
                to = mailContent.to();
            }
            if (mailContent.subject() != null) {
                subject = mailContent.subject();
            }
            if (mailContent.signatureVerified() == MailContent.SignatureVerificationResult.SignatureInvalid
                    || mailContent.signatureVerified() == MailContent.SignatureVerificationResult.SignatureVerified) {
                signatureVerified = mailContent.signatureVerified();
            }
            bodies.addAll(mailContent.bodies() != null ? mailContent.bodies() : List.of());
            attachments.addAll(mailContent.attachments() != null ? mailContent.attachments() : List.of());
        }
        return new MailContent(from, to, subject, bodies, attachments, signatureVerified);
    }

    /**
     * Converts a BodyPart to canonical CRLF bytes for signing.
     */
    private static byte[] getCanonicalBytes(MimeBodyPart bodyPart) throws IOException, MessagingException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        // Use the wrapper to force CRLF during serialization
        bodyPart.writeTo(buffer);
        return buffer.toByteArray();
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
    private static byte[] dearmorKey(byte[] armoredKeyBytes) throws IOException {
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

}
