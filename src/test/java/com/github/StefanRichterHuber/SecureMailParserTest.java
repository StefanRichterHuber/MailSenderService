package com.github.StefanRichterHuber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.PrivateKeyProvider;
import com.github.StefanRichterHuber.MailSenderService.SecureMailService;
import com.github.StefanRichterHuber.MailSenderService.config.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.models.MailContent;
import com.github.StefanRichterHuber.MailSenderService.models.RecipientWithCert;
import com.google.common.io.Files;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import sop.SOP;

@QuarkusTest
public class SecureMailParserTest {

    @Inject
    SecureMailService secureMailSender;

    @Inject
    PrivateKeyProvider privateKeyProvider;

    @Inject
    @ConfigProperty(name = "mail.to")
    InternetAddress to;

    @Inject
    @ConfigProperty(name = "smtp.from")
    InternetAddress to2;

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    Logger logger;

    private static final SOP sop = new org.pgpainless.sop.SOPImpl();

    @Test
    public void testAutoCryptHeader() throws Exception {
        var mail = createMail(true, true);
        List<RecipientWithCert> autocrypt = this.secureMailSender.parseAutocryptHeader(mail);
        assertNotNull(autocrypt);
        assertEquals(1, autocrypt.size());
        RecipientWithCert cert = autocrypt.get(0);
        assertEquals(smtpConfig.from(), cert.address());

        // Now check if this is valid public key
        byte[] encrypted = sop.encrypt().withCert(cert.cert())
                .plaintext(SecureMailSenderTest.BODY.getBytes(StandardCharsets.UTF_8))
                .toByteArrayAndResult().getBytes();

        // Then check if we could decrypt with the corresponding private key
        final var keyPair = privateKeyProvider.findByMail(cert.address());

        final byte[] decrypted = sop.decrypt().withKey(keyPair.privateKey())
                .withKeyPassword(new String(keyPair.password())).ciphertext(encrypted).toByteArrayAndResult()
                .getBytes();
        final String decryptedBody = new String(decrypted, StandardCharsets.UTF_8);

        assertEquals(SecureMailSenderTest.BODY, decryptedBody);
    }

    @Test
    public void testCreateInlineSignedMail() throws Exception {
        var mail = createMail(true, true);
        final MailContent mailContent = secureMailSender.decodeMimeMessage(mail);

        verifyMailContent(mailContent, true);

    }

    @Test
    public void testCreateSignedAndEncryptedMail() throws Exception {
        var mail = createMail(true, false);
        final MailContent mailContent = secureMailSender.decodeMimeMessage(mail);

        verifyMailContent(mailContent, true);
    }

    @Test
    public void testCreateSignedMail() throws Exception {
        var mail = createMail(false, false);
        final MailContent mailContent = secureMailSender.decodeMimeMessage(mail);

        verifyMailContent(mailContent, true);
    }

    @Test
    public void testCreateMailWithMultipleRecipients() throws Exception {
        var mail = createMailForMultipleRecipients(true, true);
        final MailContent mailContent = secureMailSender.decodeMimeMessage(mail);

        verifyMailContent(mailContent, true);
    }

    private void verifyMailContent(MailContent mailContent, boolean signatureExpected)
            throws IOException, MessagingException {
        assertEquals(SecureMailSenderTest.SUBJECT, mailContent.subject());
        if (mailContent.to().size() == 1) {
            assertEquals(to2, mailContent.to().stream().findFirst().get());
        } else {
            assertTrue(mailContent.to().contains(to));
            assertTrue(mailContent.to().contains(to2));
        }
        assertEquals(smtpConfig.from(), mailContent.from());
        assertEquals(signatureExpected,
                mailContent.signatureVerified() == MailContent.SignatureVerificationResult.SignatureVerified);

        // For inline-pgp we expect two bodies one with text/plain and one with
        // text/html
        // Always search for the first body with text/plain to verify the content
        // of the mail
        for (MimeBodyPart body : mailContent.bodies()) {
            if (body.getContentType().contains("text/plain")) {
                assertEquals(SecureMailSenderTest.BODY, body.getContent().toString());
                break;
            }
        }

        // Verify the attachments
        assertEquals(3, mailContent.attachments().size());

        for (DataSource attachment : mailContent.attachments()) {
            assertTrue(attachment.getName().equals(SecureMailSenderTest.FILE1.getName())
                    || attachment.getName().equals(SecureMailSenderTest.FILE2.getName())
                    || attachment.getName().equals(SecureMailSenderTest.FILE3.getName()));

            byte[] content = attachment.getInputStream().readAllBytes();
            byte[] expectedContent = Files.asByteSource(new File(attachment.getName())).read();

            // If both arrays are not equal, save the contents for debugging
            if (!Arrays.equals(expectedContent, content)) {
                Files.asByteSink(new File("expectedContent_" + attachment.getName())).write(expectedContent);
                Files.asByteSink(new File("content_" + attachment.getName())).write(content);
            }

            assertArrayEquals(expectedContent, content);
        }
    }

    /**
     * Helper method to create a mail.
     * 
     * @param withEncryption
     * @param inline
     * @return
     * @throws Exception
     */
    private MimeMessage createMail(boolean withEncryption, boolean inline) throws Exception {
        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE1));
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE2));
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE3));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(List.of(to2), null, null,
                SecureMailSenderTest.SUBJECT, SecureMailSenderTest.BODY, true,
                withEncryption, true, inline,
                false,
                attachments);

        return mimeMessage;
    }

    /**
     * Helper method to create a mail.
     * 
     * @param withEncryption
     * @param inline
     * @return
     * @throws Exception
     */
    private MimeMessage createMailForMultipleRecipients(boolean withEncryption, boolean inline) throws Exception {
        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE1));
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE2));
        attachments.add(new FileDataSource(SecureMailSenderTest.FILE3));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(
                List.of(to, to2), null, null,
                SecureMailSenderTest.SUBJECT, SecureMailSenderTest.BODY, true,
                withEncryption, false, inline, false,
                attachments);

        return mimeMessage;
    }

}
