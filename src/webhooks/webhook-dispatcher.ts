import crypto from 'node:crypto';

export type WebhookEventType =
  | 'GenerateKey'
  | 'RotateKey'
  | 'RevokeKey'
  | 'AccessDenied'
  | 'ExportAudit';

export interface WebhookEventPayload {
  event: WebhookEventType;
  timestamp: string;
  serviceId?: string;
  keyAlias?: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
  ipAddress?: string;
}

/**
 * Dispatches real-time security event webhooks to configured endpoint URLs with HMAC-SHA256 payload signing.
 */
export class WebhookDispatcher {
  private targetUrls: string[] = [];
  private secret: string | null = null;

  constructor() {
    this.bootstrapConfiguration();
  }

  private bootstrapConfiguration(): void {
    const rawUrls = process.env.ENCLAVE_WEBHOOK_URLS;
    if (rawUrls) {
      this.targetUrls = rawUrls
        .split(',')
        .map((u) => u.trim())
        .filter((u) => u.length > 0);
    }
    this.secret = process.env.ENCLAVE_WEBHOOK_SECRET || null;
  }

  /**
   * Registers a target webhook URL dynamically.
   */
  public registerUrl(url: string): void {
    if (!this.targetUrls.includes(url)) {
      this.targetUrls.push(url);
    }
  }

  /**
   * Configures the HMAC signing secret dynamically.
   */
  public setSecret(secret: string): void {
    this.secret = secret;
  }

  /**
   * Asynchronously dispatches security event payloads to all registered target URLs.
   */
  public async dispatch(payload: WebhookEventPayload): Promise<void> {
    if (this.targetUrls.length === 0) {
      return;
    }

    const jsonPayload = JSON.stringify(payload);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Enclave-Security-Webhook/1.0',
    };

    if (this.secret) {
      const hmac = crypto.createHmac('sha256', this.secret).update(jsonPayload).digest('hex');
      headers['X-Enclave-Signature'] = `sha256=${hmac}`;
    }

    const fetchPromises = this.targetUrls.map(async (url) => {
      try {
        await fetch(url, {
          method: 'POST',
          headers,
          body: jsonPayload,
          signal: AbortSignal.timeout(5000),
        });
      } catch (err) {
        // Non-blocking dispatch failure
      }
    });

    await Promise.allSettled(fetchPromises);
  }

  /**
   * Computes HMAC-SHA256 signature for payload verification testing.
   */
  public computeSignature(jsonPayload: string, secret: string): string {
    return `sha256=${crypto.createHmac('sha256', secret).update(jsonPayload).digest('hex')}`;
  }
}
