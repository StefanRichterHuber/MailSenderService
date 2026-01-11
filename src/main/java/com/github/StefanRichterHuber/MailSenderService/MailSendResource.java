package com.github.StefanRichterHuber.MailSenderService;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;

import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

@Path("/sendmail")
@ApplicationScoped
public class MailSendResource {

    @Inject
    SecureMailService mailFactory;

    /**
     * Sends a mail with the given parameters.
     * 
     * Warning: This endpoint is not secure! Only use it in a trusted environment!
     * 
     * @param to      The recipient's email address.
     * @param subject The subject of the email.
     * @param body    The body of the email.
     * @param sign    Whether to sign the email.
     * @param encrypt Whether to encrypt the email.
     * @param files   The attachments to the email. Can be null.
     * @throws AddressException
     * @throws Exception
     */
    @POST
    public void multipart(
            @RestForm List<String> to,
            @RestForm List<String> cc,
            @RestForm List<String> bcc,
            @RestForm String subject,
            @RestForm String body,
            @RestForm boolean sign,
            @RestForm boolean encrypt,
            @RestForm(FileUpload.ALL) List<FileUpload> files) throws AddressException, Exception {

        // Convert all FileUpload to DataSource
        final List<DataSource> attachments = files != null ? files.stream()
                .map(fileUpload -> new FileDataSource(fileUpload.filePath().toFile()))
                .collect(Collectors.toList()) : Collections.emptyList();

        final List<InternetAddress> toAddresses = toInternetAddressList(to);
        final List<InternetAddress> ccAddresses = toInternetAddressList(cc);
        final List<InternetAddress> bccAddresses = toInternetAddressList(bcc);

        mailFactory.sendMail(toAddresses, ccAddresses, bccAddresses, subject, body, sign, encrypt, attachments);
    }

    /**
     * Converts a list of email addresses to a list of InternetAddress objects.
     * 
     * @param addresses The list of email addresses.
     * @return The list of InternetAddress objects.
     */
    private List<InternetAddress> toInternetAddressList(Collection<String> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return Collections.emptyList();
        }
        return addresses.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(t -> !t.isEmpty())
                .map(t -> {
                    try {
                        return new InternetAddress(t);
                    } catch (AddressException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }
}
