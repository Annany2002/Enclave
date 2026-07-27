export interface TransportConfig {
  baseUrl: string;
  authToken: string;
  maxRetries?: number;
  timeoutMs?: number;
}

export class EnclaveTransport {
  private baseUrl: string;
  private authToken: string;
  private maxRetries: number;
  private timeoutMs: number;

  constructor(config: TransportConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.authToken = config.authToken;
    this.maxRetries = config.maxRetries ?? 3;
    this.timeoutMs = config.timeoutMs ?? 5000;
  }

  public async request<T>(path: string, body?: unknown): Promise<T> {
    let attempt = 0;
    let delay = 100;

    while (attempt <= this.maxRetries) {
      attempt++;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

        const response = await fetch(`${this.baseUrl}${path}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.authToken}`,
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const errText = await response.text();
          if (response.status >= 500 && attempt <= this.maxRetries) {
            await this.sleep(delay);
            delay *= 2;
            continue;
          }
          throw new Error(`Enclave API Error [${response.status}]: ${errText}`);
        }

        return (await response.json()) as T;
      } catch (err: any) {
        if (attempt > this.maxRetries) {
          throw new Error(`Enclave Network Request failed after ${this.maxRetries} retries: ${err.message}`);
        }
        await this.sleep(delay);
        delay *= 2;
      }
    }

    throw new Error('Enclave Request failed unexpected exit from retry loop.');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
