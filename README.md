# MailSenderService

This Java project based on the Quarkus framework shows how to leverage [pgpainless-sop](https://github.com/pgpainless/pgpainless) to create and send compliant (as far as possible) PGP encrypted and signed emails.

## Features

### Searching for public keys

In order to encrypt a message, the public key of the recipient is required. These keys could be either provided by the recipient itself (manually or via Autocrypt header in the message) or retrieved from a public key server. Retrieving the key from the recipient is not in scope of this project. It is expected that the public key is available on a (public) key server.

This project uses VKS (like [keys.openpgp.org](https://keys.openpgp.org)) and Mailvelope (like [https://keys.mailvelope.com/](https://keys.mailvelope.com/)) compatible key servers to search for the public keys for a recpients mail address. Use `com.github.StefanRichterHuber.MailSenderService.PublicKeySearchService.findByMail(String)` to search for a public key. [Quarkus Application Data Caching](https://quarkus.io/guides/cache) is used to cache the looked up public keys to avoid both uneccessary load on this free servers as well as to speed up the lookup process.

### Building compliant MIME Messages

In general there a two modes to transport PGP encrypted and signed emails:

#### Inline PGP (recommended)

Inline PGP is the most compatible format (tested with [Mailvelope Browser Extension](https://mailvelope.com), Thunderbird and K9 Mail). This is an older, legacy method where the encrypted ASCII block is simply pasted into the `text/plain` or `text/html` body of the email. It is more compatible with web clients and therefore the Mailvelope Browser Extension. It is however, less secure, since it only works with detached encrypted attachments, which need to be seperatly decrypted. File names of the attachments are still visible in the email (with an addced `.asc` extension). Moreover inline PGP does not support protected headers (so the actual `Subject` header is always visible) and signed-only messages.

#### PGP/MIME

PGP/MIME (RFC 3156) is the most secure and modern format, however, less compatible (tested with K9 Mail and Thunderbird). It supports protected headers, especially the `Subject` header (as of now, not available for K9 Mail) and fully encrypted attachments (both file content and file name). Compatible clients can decrypt, verify the signature and display the message and the attachments all in one go. Signed-only messages are available in PGP/MIME mode.

See class `com.github.StefanRichterHuber.MailSenderService.SecureMailService` to build a MIME message which can be signed and / or encrypted, including encrypted attachments with an optional Autocrypt header. Both encrypted and signed multipart messages including attachments and protected headers as well as inline PGP with detached signatures are supported.

#### Autocrypt

The `Autocrypt` header is optional and can be added to the MIME message to enable clients to automatically import the public key of the sender. It contains the sender`s mail address and the public key of the sender. It can be added to all kind of messages, signed and encrypted or not.

### Reading and Verifying PGP Messages

See class `com.github.StefanRichterHuber.MailSenderService.SecureMailService.decodeMimeMessage(MimeMessage)` to read and verify PGP messages. It supports reading and verifying signed and encrypted multipart messages including attachments and protected headers as well as inline PGP with detached signatures.

## Testing

Some test classes are provided to test the functionality of the project. They can be run with `mvn test`. They generate EML files in the root directory. They can be opened with a compatible mail client to test the functionality of the project. 

The tests require some configuration values to work, usually provided as `.env` file in the root directory. Key servers `https://keys.openpgp.org` and `https://keys.mailvelope.com` are pre-configured to search for the public keys of the recipients (depending on the protcol either change `SMTP_VKS_KEY_SERVERS` or `SMTP_MAILVELOPE_KEY_SERVERS` environment variables to use a different key server). To test the key-lookup functionality, generate an OpenPGP key pair for a test recipient and add the public key to one of the key servers. Then set the `MAIL_TO` environment variable to the test recipient's email address.

```shell
# File containing the sender's privat and public key (ascii armoured format). Required for generating signed and encrypted emails.
SMTP_SENDER_SECRET_KEY_FILE=[SENDER SECRET KEY FILE]
# Password for the sender's private key. Required for generating signed and encrypted emails.
SMTP_SENDER_SECRET_KEY_PASSWORD=[SENDER SECRET KEY PASSWORD]

# Configuration values for the SMTP server. Real values only required for sending an email. To just generate eml files, add dummy values.
SMTP_AUTH_ENABLED=[true / false]
SMTP_SSL_ENABLED=[true / false]
SMTP_USER=[SENDER EMAIL]
SMTP_HOST=[SMPT HOST]
SMTP_PORT=[SMTP PORT]
SMTP_FROM=[SENDER EMAIL]
SMTP_PASSWORD=[SENDER PASSWORD]

# Recipient of the test email. Required for actually sending an email.
MAIL_TO=[RECIPIENT EMAIL]
```
