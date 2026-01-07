# MailSenderService

This Java project based on the Quarkus framework shows how to leverage [pgpainless-sop](https://github.com/pgpainless/pgpainless) to create and send compliant (as far as possible) PGP encrypted and signed emails.

## Features

### Searching for public keys

Using VKS (like [keys.openpgp.org](https://keys.openpgp.org)) and Mailvelope like ([https://keys.mailvelope.com/](https://keys.mailvelope.com/)) compatible key servers to search for the public keys for a recpients mail address. Use `com.github.StefanRichterHuber.MailSenderService.PublicKeySearchService.findByMail(String)` to search for a public key.

### Buildin compliant MIME Messages

The `Autocrypt` header is optional and can be added to the MIME message to enable clients to automatically import the public key of the sender. It contains the sender`s mail address and the public key of the sender. It can be added to all kind of messages, signed and encrypted or not.

In general there a two modes to transport PGP encrypted and signed emails:

#### Inline PGP (recommended)

Inline PGP is the most compatible format (tested with [Mailvelope Browser Extension](https://mailvelope.com), Thunderbird and K9 Mail). It is however, less convenient, since they only work with detached encrypted attachments, which need to be seperatly decrypted. and do not support protected headers. Signed-only messages are not available in inline PGP mode. Moreover file names of the attachments are still visible in the email (with an addced `.asc` extension).

#### Multipart PGP

Multipart PGP is the most secure format, however, less compatible (tested with K9 Mail and Thunderbird). It supports protected headers (not with K9 Mail) and encrypted attachments. Compatible clients can decrypt, verify the signature and display the message and the attachments all in one go. File names of the attachments are not visible in the email. Signed-only messages are available in multipart PGP mode.

See class `com.github.StefanRichterHuber.MailSenderService.SecureMailService` to build a MIME message which can be signed and / or encrypted, including encrypted attachments with an optional Autocrypt header. Both encrypted and signed multipart messages including attachments and protected headers as well as inline PGP with detached signatures are supported.

### Sending an email

See class `com.github.StefanRichterHuber.MailSenderService.SessionFactory` to build a `jakarta.mail.Session` and `com.github.StefanRichterHuber.MailSenderService.SMTPService` to send an email.

## Testing

Some test classes are provided to test the functionality of the project. They can be run with `mvn test`. They generate EML files in the root directory. They can be opened with a compatible mail client to test the functionality of the project. 

The tests require some configuration values to work, usually provided as `.env` file in the root directory. Key servers `https://keys.openpgp.org` and `https://keys.mailvelope.com` are pre-configured to search for the public keys of the recipients (depending on the protcol either change `SMTP_VKS_KEY_SERVERS` or `SMTP_MAILVELOPE_KEY_SERVERS` environment variables to use a different key server). To test the key-lookup functionality, generate an OpenPGP key pair for a test recipient and add the public key to one of the key servers. Then set the `MAIL_TO` environment variable to the test recipient's email address.

```shell
# File containing the sender's privat and public key (ascii armoured format). Required for generating signed and encrypted emails.
SMTP_SENDER_SECRET_KEY_FILE=[SENDER SECRET KEY FILE]
# Password for the sender's private key. Required for generating signed and encrypted emails.
SMTP_SENDER_SECRET_KEY_PASSWORD=[SENDER SECRET KEY PASSWORD]

# Configuration values for the SMTP server. Real values only required for sending an email. For generation eml files, just add dummy values.
SMTP_AUTH_ENABLED=[true / false]
SMTP_SSL_ENABLED=[true / false]
SMTP_USER=[SENDER EMAIL]
SMTP_HOST=[SMPT HOST]
SMTP_PORT=[SMTP PORT]
SMTP_FROM=[SENDER EMAIL]
SMTP_PASSWORD=[SENDER PASSWORD]

# Recipient of the test email. Required for sending an email.
MAIL_TO=[RECIPIENT EMAIL]
```
