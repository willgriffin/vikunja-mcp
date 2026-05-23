import { createHmac } from 'node:crypto';
import { verifyVikunjaWebhookSignature } from '../../src/updates/webhook-signature';

describe('Vikunja webhook signature verification', () => {
  it('accepts valid HMAC signatures', () => {
    const body = JSON.stringify({ event_name: 'task.updated' });
    const secret = 'vikunja-webhook-secret';
    const signature = createHmac('sha256', secret).update(body).digest('hex');

    expect(verifyVikunjaWebhookSignature(body, signature, secret)).toBe(true);
  });

  it('rejects invalid HMAC signatures', () => {
    const body = JSON.stringify({ event_name: 'task.updated' });

    expect(verifyVikunjaWebhookSignature(body, '00', 'vikunja-webhook-secret')).toBe(false);
  });

  it('rejects unsigned webhooks when no secret is configured', () => {
    expect(verifyVikunjaWebhookSignature('{}', undefined, undefined)).toBe(false);
    expect(verifyVikunjaWebhookSignature('{}', undefined, 'vikunja-webhook-secret')).toBe(false);
  });
});
