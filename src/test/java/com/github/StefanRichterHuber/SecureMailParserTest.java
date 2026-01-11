package com.github.StefanRichterHuber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.SecureMailService;
import com.github.StefanRichterHuber.MailSenderService.config.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.models.MailContent;
import com.google.common.io.Files;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailParserTest {

    private static final File FILE1 = new File("README.md");
    private static final File FILE2 = new File("pom.xml");

    private static final String BODY = "Here is the requested document.";

    private static final String SUBJECT = "Secure Document";

    @Inject
    SecureMailService secureMailSender;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Inject
    @ConfigProperty(name = "smtp.from")
    String to2;

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    Logger logger;

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
        assertEquals(SUBJECT, mailContent.subject());
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
                assertEquals(BODY, body.getContent().toString());
                break;
            }
        }

        // Verify the attachments
        assertEquals(2, mailContent.attachments().size());

        for (DataSource attachment : mailContent.attachments()) {
            assertTrue(attachment.getName().equals(FILE1.getName()) || attachment.getName().equals(FILE2.getName()));

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
        attachments.add(new FileDataSource(FILE1));
        attachments.add(new FileDataSource(FILE2));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(List.of(new InternetAddress(to2)), null, null,
                SUBJECT, BODY, true,
                withEncryption, false, inline,
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
        attachments.add(new FileDataSource(FILE1));
        attachments.add(new FileDataSource(FILE2));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(
                List.of(new InternetAddress(to), new InternetAddress(to2)), null, null,
                SUBJECT, BODY, true,
                withEncryption, false, inline, false,
                attachments);

        return mimeMessage;
    }

}
