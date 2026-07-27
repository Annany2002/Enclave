import { CryptoEngine } from '../crypto/crypto-engine.js';

export type EnclaveOperation = 'Encrypt' | 'Decrypt' | 'GenerateKey' | 'RotateKey' | 'GetKey' | '*';

export interface ServiceIdentity {
  serviceId: string;
  token?: string;
  clientCertCn?: string;
  allowedKeyAliases: string[];
  allowedOperations: EnclaveOperation[];
}

export class IAMManager {
  private serviceRegistry: Map<string, ServiceIdentity> = new Map();

  constructor() {
    this.registerDefaultPolicies();
  }

  private registerDefaultPolicies(): void {
    const rawPolicies = process.env.ENCLAVE_RBAC_POLICIES || process.env.KMS_RBAC_POLICIES;
    if (rawPolicies) {
      try {
        const parsed: ServiceIdentity[] = JSON.parse(rawPolicies);
        for (const svc of parsed) {
          this.registerService(svc);
        }
      } catch (err) {
        throw new Error(`Failed to parse ENCLAVE_RBAC_POLICIES env: ${err}`);
      }
    }
  }

  public registerService(identity: ServiceIdentity): void {
    this.serviceRegistry.set(identity.serviceId, identity);
  }

  public authenticateToken(token: string): ServiceIdentity | null {
    if (!token) return null;

    for (const identity of this.serviceRegistry.values()) {
      if (identity.token && CryptoEngine.timingSafeCompare(identity.token, token)) {
        return identity;
      }
    }

    return null;
  }

  public authenticateMtlsCert(clientCn: string): ServiceIdentity | null {
    if (!clientCn) return null;

    for (const identity of this.serviceRegistry.values()) {
      if (identity.clientCertCn && CryptoEngine.timingSafeCompare(identity.clientCertCn, clientCn)) {
        return identity;
      }
    }

    return null;
  }

  public authorize(
    identity: ServiceIdentity,
    keyAlias: string,
    operation: EnclaveOperation
  ): boolean {
    const hasOpPermission =
      identity.allowedOperations.includes(operation) ||
      identity.allowedOperations.includes('*' as EnclaveOperation);

    if (!hasOpPermission) {
      return false;
    }

    const hasKeyPermission =
      identity.allowedKeyAliases.includes(keyAlias) ||
      identity.allowedKeyAliases.includes('*');

    return hasKeyPermission;
  }
}
