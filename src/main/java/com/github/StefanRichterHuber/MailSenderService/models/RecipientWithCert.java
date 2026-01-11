package com.github.StefanRichterHuber.MailSenderService.models;

import jakarta.mail.internet.InternetAddress;

/**
 * Container for a recipient and its public certificate.
 */
public record RecipientWithCert(InternetAddress address, byte[] cert) {
}