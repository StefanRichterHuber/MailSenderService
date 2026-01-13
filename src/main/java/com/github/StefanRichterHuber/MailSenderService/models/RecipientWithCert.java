package com.github.StefanRichterHuber.MailSenderService.models;

import jakarta.mail.Address;

/**
 * Container for a recipient and its public certificate.
 */
public record RecipientWithCert(Address address, byte[] cert) {
}