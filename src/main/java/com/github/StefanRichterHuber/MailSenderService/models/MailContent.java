package com.github.StefanRichterHuber.MailSenderService.models;

import java.util.Collection;
import java.util.Set;

import jakarta.activation.DataSource;
import jakarta.mail.Address;
import jakarta.mail.internet.MimeBodyPart;

public record MailContent(Address from,
        Set<? extends Address> to,
        Set<? extends Address> cc,
        Set<? extends Address> bcc,
        String subject,
        Collection<? extends MimeBodyPart> bodies,
        Collection<? extends DataSource> attachments,
        SignatureVerificationResult signatureVerified) {

    public static enum SignatureVerificationResult {
        NoSignature,
        SignatureVerified,
        SignatureInvalid
    }
}