package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.SecureMailService;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

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
    @ConfigProperty(name = "mail.to2")
    String to2;

    /**
     * Creates an inline signed mail and writes it to disk.
     * 
     * @throws Exception
     */
    @Test
    public void testCreateInlineSignedMail() throws Exception {

        var mail = sendMail(true, true);
        writeMailToDisk(mail, true, true);
    }

    /**
     * Creates a signed and encrypted mail and writes it to disk.
     * 
     * @throws Exception
     */
    @Test
    public void testCreateSignedAndEncryptedMail() throws Exception {
        var mail = sendMail(true, false);

        secureMailSender.addAutocryptHeader(mail);
        writeMailToDisk(mail, true, false);

    }

    /**
     * Creates a signed mail and writes it to disk.
     * 
     * @throws Exception
     */
    @Test
    public void testCreateSignedMail() throws Exception {
        var mail = sendMail(false, false);

        secureMailSender.addAutocryptHeader(mail);
        writeMailToDisk(mail, false, false);

    }

    @Test
    @Disabled("Really sends a mail")
    void testSendInlineSignedMail() throws Exception {
        var mail = sendMail(true, true);
        Transport.send(mail);
    }

    @Test
    @Disabled("Really sends a mail")
    public void testSendMail() throws Exception {
        var mail = sendMail(true, false);
        Transport.send(mail);
    }

    @Test
    public void testCreateInlineEncryptedMailWithMultipleRecipients() throws Exception {
        var mail = sendMailToMultipleRecipients(true, true);

        String filename = "inline_signed_encrypted_mail_with_multiple_recipients.eml";

        try (OutputStream out = new FileOutputStream(filename)) {
            mail.writeTo(out);
        }
        System.out.println("Email generated: " + filename);
    }

    @Test
    public void testCreateEncryptedMailWithMultipleRecipients() throws Exception {
        var mail = sendMailToMultipleRecipients(true, false);

        String filename = "signed_encrypted_mail_with_multiple_recipients.eml";

        try (OutputStream out = new FileOutputStream(filename)) {
            mail.writeTo(out);
        }
        System.out.println("Email generated: " + filename);
    }

    /**
     * Helper method to create a mail.
     * 
     * @param withEncryption
     * @param inline
     * @return
     * @throws Exception
     */
    private MimeMessage sendMail(boolean withEncryption, boolean inline) throws Exception {
        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(FILE1));
        attachments.add(new FileDataSource(FILE2));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(List.of(new InternetAddress(to)), null, null,
                SUBJECT, BODY, true,
                withEncryption, false, inline, false,
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
    private MimeMessage sendMailToMultipleRecipients(boolean withEncryption, boolean inline) throws Exception {
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

    /**
     * Helper method to write a mail to disk.
     * 
     * @param message
     * @param withEncryption
     * @param inline
     * @throws Exception
     */
    private void writeMailToDisk(MimeMessage message, boolean withEncryption, boolean inline) throws Exception {
        String filename = withEncryption ? "signed_encrypted_email.eml" : "signed_email.eml";
        if (inline) {
            filename = "inline_" + filename;
        }

        try (OutputStream out = new FileOutputStream(filename)) {
            message.writeTo(out);
        }
        System.out.println("Email generated: " + filename);
    }

}