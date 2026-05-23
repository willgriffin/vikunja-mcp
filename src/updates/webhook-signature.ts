import { createHmac, timingSafeEqual } from 'node:crypto';

export function verifyVikunjaWebhookSignature(
  rawBody: string,
  signature: string | string[] | undefined,
  secret: string | undefined,
): boolean {
  if (!secret) {
    return true;
  }

  const providedSignature = Array.isArray(signature) ? signature[0] : signature;
  if (!providedSignature) {
    return false;
  }

  const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  const providedBuffer = Buffer.from(providedSignature, 'hex');

  if (expectedBuffer.length === 0 || expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, providedBuffer);
}
