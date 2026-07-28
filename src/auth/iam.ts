import { CryptoEngine } from '../crypto/crypto-engine.js';

export type EnclaveOperation =
  | 'Encrypt'
  | 'Decrypt'
  | 'GenerateKey'
  | 'RotateKey'
  | 'RevokeKey'
  | 'GetKey'
  | 'ExportAudit'
  | '*';

export interface ServiceIdentity {
  serviceId: string;
  token?: string;
  clientCertCn?: string;
  allowedKeyAliases: string[];
  allowedOperations: EnclaveOperation[];
}

/**
 * Identity Access Management & Role-Based Access Control evaluator.
 * Authenticates microservices via Bearer tokens or mTLS certificates and validates permissions.
 * 
 * @remark **Bearer Token Prefix**: `enc_tok_` (e.g. `enc_tok_billing_d45c7666...`)
 */
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

  /**
   * Registers a microservice identity and permissions policy.
   */
  public registerService(identity: ServiceIdentity): void {
    this.serviceRegistry.set(identity.serviceId, identity);
  }

  /**
   * Authenticates caller via Bearer token in constant time.
   * 
   * @remark **Bearer Token Prefix**: `enc_tok_`
   */
  public authenticateToken(token: string): ServiceIdentity | null {
    if (!token) return null;

    for (const identity of this.serviceRegistry.values()) {
      if (identity.token && CryptoEngine.timingSafeCompare(identity.token, token)) {
        return identity;
      }
    }

    return null;
  }

  /**
   * Authenticates caller via mTLS client certificate Subject CN header.
   */
  public authenticateMtlsCert(clientCn: string): ServiceIdentity | null {
    if (!clientCn) return null;

    for (const identity of this.serviceRegistry.values()) {
      if (identity.clientCertCn && CryptoEngine.timingSafeCompare(identity.clientCertCn, clientCn)) {
        return identity;
      }
    }

    return null;
  }

  /**
   * Evaluates RBAC permissions for a target key alias and requested operation.
   */
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

    if (keyAlias === '*' || operation === 'ExportAudit') {
      return true;
    }

    const hasKeyPermission =
      identity.allowedKeyAliases.includes(keyAlias) ||
      identity.allowedKeyAliases.includes('*');

    return hasKeyPermission;
  }
}
