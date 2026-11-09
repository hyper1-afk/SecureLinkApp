# Durable account email outbox

Account verification and password-reset messages are written in the same database transaction as their token digests. The delivery payload is encrypted with Fernet using `EMAIL_OUTBOX_ENCRYPTION_KEY`; generate it with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Store this key as a secret in each environment, back it up through the secret manager, and rotate only with an explicit re-encryption plan. Losing it makes queued messages unreadable.

The API does not send email inline. Run one or more `python -m apps.api.email_worker` processes against the same database. The worker claims rows with a database lease, sends via SMTP with STARTTLS, retries transient failures with capped exponential backoff, and removes the encrypted payload after delivery. A process crash after SMTP accepted a message but before marking it sent may cause a duplicate email; links remain single-use. Expired or consumed tokens are not delivered.

Keep `APP_PUBLIC_URL` HTTPS in staging/production. Do not log message bodies, tokens, recipient addresses, or SMTP credentials. Monitor the count and age of pending/failed rows and worker health. Requeue failed messages by issuing a fresh resend/reset request; do not manually expose token ciphertext.
