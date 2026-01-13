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

    public static final File FILE1 = new File("README.md");
    public static final File FILE2 = new File("pom.xml");
    public static final File FILE3 = new File("testimage.jpg");

    public static final List<File> ATTACHMENTS = List.of(FILE1, FILE2, FILE3);

    public static final String BODY = "Here is the requested document. Includes several special characters: \"äöü\"";

    public static final String SUBJECT = "Secure Document - with some special Chars: \"äöü\"";

    @Inject
    SecureMailService secureMailSender;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @ConfigProperty(name = "smtp.from")
    @Inject
    String to2;

    /**
     * Creates an inline signed mail and writes it to disk.
     * 
     * @throws Exception
     */
    @Test
    public void testCreateInlineSignedMail() throws Exception {

        var mail = createMail(true, true);
        writeMailToDisk(mail, true, true);
    }

    /**
     * Creates a signed and encrypted mail and writes it to disk.
     * 
     * @throws Exception
     */
    @Test
    public void testCreateSignedAndEncryptedMail() throws Exception {
        var mail = createMail(true, false);

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
        var mail = createMail(false, false);

        secureMailSender.addAutocryptHeader(mail);
        writeMailToDisk(mail, false, false);

    }

    @Test
    @Disabled("Really sends a mail")
    void testSendInlineSignedMail() throws Exception {
        var mail = createMail(true, true);
        Transport.send(mail);
    }

    @Test
    @Disabled("Really sends a mail")
    public void testSendMail() throws Exception {
        var mail = createMail(true, false);
        Transport.send(mail);
    }

    @Test
    public void testCreateInlineEncryptedMailWithMultipleRecipients() throws Exception {
        var mail = createMailForMultipleRecipients(true, true);

        String filename = "inline_signed_encrypted_mail_with_multiple_recipients.eml";

        try (OutputStream out = new FileOutputStream(filename)) {
            mail.writeTo(out);
        }
        System.out.println("Email generated: " + filename);
    }

    @Test
    public void testCreateEncryptedMailWithMultipleRecipients() throws Exception {
        var mail = createMailForMultipleRecipients(true, false);

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
    private MimeMessage createMail(boolean withEncryption, boolean inline) throws Exception {
        List<? extends DataSource> attachments = ATTACHMENTS.stream().map(FileDataSource::new).toList();
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
    private MimeMessage createMailForMultipleRecipients(boolean withEncryption, boolean inline) throws Exception {
        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(FILE1));
        attachments.add(new FileDataSource(FILE2));
        attachments.add(new FileDataSource(FILE3));

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