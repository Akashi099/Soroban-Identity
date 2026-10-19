import { StrKey } from "@stellar/stellar-sdk";

/**
 * W3C DID Core service endpoint embedded in a {@link DidDocument}.
 *
 * Mirrors the Rust `ServiceEndpoint` contracttype from the identity-registry.
 * Note: the Soroban field is named `type_` (reserved keyword in Rust); this
 * interface follows the same serialisation name.
 *
 * @see https://www.w3.org/TR/did-core/#services
 */
export interface ServiceEndpoint {
  /** URI identifying this endpoint (e.g. `did:stellar:…#messaging`). */
  id: string;
  /** Service type (e.g. `DIDCommMessaging`, `CredentialService`). */
  type_: string;
  /** URL or URI where the service can be reached. */
  service_endpoint: string;
}

/**
 * Decentralised identifier document as stored by the identity-registry contract.
 *
 * `id` follows the `did:stellar:<address>` form. `metadata` is a free-form
 * `string → string` map the controller can update via
 * {@link IdentityClient.updateDid}.
 */
export interface DidDocument {
  /** Full DID — `did:stellar:<address>`. */
  id: string;
  /** Stellar address with authority to update or deactivate this DID. */
  controller: string;
  /** Arbitrary key-value metadata associated with the DID. */
  metadata: Record<string, string>;
  /** Unix timestamp (seconds) of initial creation. */
  createdAt: number;
  /** Unix timestamp (seconds) of last metadata update. */
  updatedAt: number;
  /** `false` once `deactivateDid` has been called for this DID. */
  active: boolean;
  /**
   * Optional W3C DID Core service endpoints.
   * Empty array by default; updated via the identity-registry admin flow.
   */
  services: ServiceEndpoint[];
}

const VALID_CREDENTIAL_TYPES = ["Kyc", "Reputation", "Achievement", "Custom"] as const;

/**
 * Credential category recognised by the credential-manager contract.
 * `Custom` is the catch-all for application-defined types.
 */
export type CredentialType = (typeof VALID_CREDENTIAL_TYPES)[number];

export class UnknownCredentialTypeError extends Error {
  constructor(value: unknown) {
    super(`UnknownCredentialTypeError: unexpected credential type "${String(value)}"`);
    this.name = "UnknownCredentialTypeError";
  }
}

export function assertCredentialType(value: unknown): CredentialType {
  if (typeof value === "string" && VALID_CREDENTIAL_TYPES.includes(value as CredentialType)) {
    return value as CredentialType;
  }

  throw new UnknownCredentialTypeError(value);
}

/**
 * On-chain credential record returned by
 * {@link CredentialClient.getCredential}.
 */
export interface CredentialVersionEntry {
  version: number;
  amendedAt: number;
  amendedBy: string;
  reason: string;
  changeSummary: string;
}

export interface Credential {
  id: string; // hex-encoded 32-byte hash
  subject: string;
  issuer: string;
  credentialType: CredentialType;
  claims: Record<string, string>;
  /** SHA-256 hash of the off-chain claims payload (hex-encoded 32 bytes) */
  claimsHash: string;
  signature: string; // hex
  issuedAt: number;
  version: number;
  lastModifiedAt: number;
  versionHistory?: CredentialVersionEntry[];
  /**
   * Unix timestamp (seconds) before which this credential is inactive.
   * `0` means the credential is active immediately (no time-lock). #731
   */
  activationTime: number;
  expiresAt: number; // 0 = no expiry
  revoked: boolean;
  /**
   * `true` when the issuer has cancelled a pending time-locked activation
   * before the `activationTime` was reached. A cancelled credential is
   * permanently inactive. #731
   */
  activationCancelled: boolean;
}

/**
 * A credential that has been revoked, returned by
 * {@link CredentialClient.revokeCredential}.
 *
 * Extends {@link Credential} with a required `revokedAt` ISO-8601 timestamp
 * derived from the ledger close time of the revocation transaction, and a
 * discriminant `status` field so callers can narrow the type without
 * inspecting `revoked`.
 */

/**
 * Reasons a credential can be revoked with. Mirrors the contract's
 * `RevocationReason` enum (#937).
 *
 * The values are the contract's variant names and are part of the wire format:
 * never rename or reorder them. Use {@link normalizeRevocationReason} for values
 * that come from user input (CSV imports, CLI flags) — it also accepts the
 * snake_case labels the contract stores (`admin_revoked`).
 */
export const RevocationReason = {
  Compromised: "Compromised",
  Expired: "Expired",
  Superseded: "Superseded",
  Lost: "Lost",
  AdminRevoked: "AdminRevoked",
} as const;

export type RevocationReason = (typeof RevocationReason)[keyof typeof RevocationReason];

/** Every reason, in the contract's declaration order — use this for pickers. */
export const REVOCATION_REASONS: readonly RevocationReason[] = [
  RevocationReason.Compromised,
  RevocationReason.Expired,
  RevocationReason.Superseded,
  RevocationReason.Lost,
  RevocationReason.AdminRevoked,
];

/** Human-readable labels, keyed by reason. */
export const REVOCATION_REASON_LABELS: Record<RevocationReason, string> = {
  [RevocationReason.Compromised]: "Compromised",
  [RevocationReason.Expired]: "Expired",
  [RevocationReason.Superseded]: "Superseded",
  [RevocationReason.Lost]: "Lost",
  [RevocationReason.AdminRevoked]: "Admin revoked",
};

/** True when `value` is already a {@link RevocationReason}. */
export function isRevocationReason(value: unknown): value is RevocationReason {
  return typeof value === "string" && (REVOCATION_REASONS as readonly string[]).includes(value);
}

/**
 * Map user input to a {@link RevocationReason}.
 *
 * Accepts the exact enum value (`Superseded`), the contract's stored label
 * (`superseded`), spaces or dashes instead of underscores (`admin revoked`)
 * and any casing of those. Returns `undefined` for anything else, so callers
 * can report the offending value instead of revoking for the wrong reason.
 */
export function normalizeRevocationReason(value: unknown): RevocationReason | undefined {
  if (value === undefined || value === null) return undefined;
  if (isRevocationReason(value)) return value;
  if (typeof value !== "string") return undefined;

  const compact = value.trim().toLowerCase().replace(/[\s_-]+/g, "");
  if (compact.length === 0) return undefined;
  return REVOCATION_REASONS.find(
    (reason) => reason.toLowerCase().replace(/[\s_-]+/g, "") === compact
  );
}

/**
 * A revocation record as stored by the contract (read back with
 * `get_revocation`, #937).
 */
export interface RevocationRecord {
  credentialId: string;
  issuer: string;
  subject: string;
  reason: RevocationReason;
  /** Unix timestamp (seconds) of the ledger that recorded the revocation. */
  revokedAt: number;
  /** Address that submitted the revocation, when the contract returns it. */
  revokedBy?: string;
}

export interface RevokedCredential extends Credential {
  /** ISO-8601 timestamp of the ledger that included the revocation transaction. */
  revokedAt: string;
  status: 'revoked';
  /** Standardized reason recorded on-chain for the revocation. #951 */
  revocationReason?: RevocationReason;
}

/** Options for {@link CredentialClient.revokeCredential}. */
export interface RevokeOptions extends CallOptions {
  /** Standardized revocation reason. Omit to revoke without a reason code. */
  reason?: RevocationReason;
}

/**
 * Reason a credential is invalid. Returned in {@link VerifyResult}.
 *
 * - `EXPIRED` — the credential's `expiresAt` timestamp has passed.
 * - `REVOKED` — the issuer has explicitly revoked the credential.
 * - `INVALID_SIGNATURE` — the stored issuer signature does not match.
 * - `UNKNOWN_ISSUER` — no credential was found for the given ID, or the
 *   credential's issuer is no longer registered.
 * - `INACTIVE_SUBJECT` — the subject's DID has been deactivated.
 * - `not_yet_active` — the credential's `activationTime` has not been reached yet. #731
 */
export type VerifyFailReason =
  | 'not_found'
  | 'revoked'
  | 'expired'
  | 'not_yet_active'
  | 'unknown'
  | 'EXPIRED'
  | 'REVOKED'
  | 'INVALID_SIGNATURE'
  | 'UNKNOWN_ISSUER'
  | 'INACTIVE_SUBJECT';

/**
 * Result from {@link CredentialClient.verifyCredential}.
 *
 * `valid` is `true` when the credential is active and unexpired.
 * `reason` is present when `valid` is `false` and a specific failure cause
 * could be determined from the contract's typed error response.
 */
export type VerifyResult = { valid: boolean; reason?: VerifyFailReason };

export interface SorobanIdentityLogger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info?(message: string, meta?: Record<string, unknown>): void;
  warn?(message: string, meta?: Record<string, unknown>): void;
  error?(message: string, meta?: Record<string, unknown>): void;
}

export interface ReputationRecord {
  subject: string;
  score: number;
  reporterCount: number;
  updatedAt: number;
}

export interface ScoreHistoryEntry {
  reporter: string;
  delta: number;
  reason: string;
  submittedAt: number;
}

export interface SorobanIdentityConfig {
  rpcUrl: string | string[];
  networkPassphrase: string;
  identityRegistryId: string;
  credentialManagerId: string;
  /** Contract ID for the reputation contract. Required when using {@link ReputationClient}. */
  reputationId: string;
  /** Transaction timeout in seconds. Defaults to 30. */
  txTimeout?: number;
  /**
   * Default wall-clock timeout in milliseconds for write operations such as
   * `issueCredential`. When the timeout elapses the call rejects with
   * `SorobanIdentityError` code `TIMEOUT`. Defaults to 30 000 ms.
   * Override per-call via `CallOptions.timeoutMs`.
   */
  defaultTimeoutMs?: number;
  /** Maximum concurrent RPC requests. Defaults to 5. */
  maxConcurrentRequests?: number;
  /** Request retry delay in ms. Defaults to 1000. */
  retryDelay?: number;
  /**
   * Maximum retry/attempt count. For transient RPC retry loops this defaults to
   * 3; for transaction-status polling it defaults to 15 attempts. With the
   * default `retryIntervalMs` of 2000ms, polling preserves the previous
   * effective 30s confirmation window. Set to 0 to disable retries/attempts.
   */
  maxRetries?: number;
  /** Base delay in ms between `resolveDid` retries. Defaults to 500. */
  baseDelayMs?: number;
  /** Multiplier applied to the delay on each successive retry. Defaults to 2. */
  backoffFactor?: number;
  /**
   * Fixed delay in milliseconds between transaction-status polling attempts.
   * Defaults to 2000ms; `maxRetries * retryIntervalMs` is the maximum wait.
   */
  retryIntervalMs?: number;
  /** @deprecated Use `maxRetries` instead. */
  pollingRetries?: number;
  /** @deprecated Use `retryIntervalMs` instead. */
  pollingIntervalMs?: number;
  /** Whether to use exponential backoff between polling attempts. Defaults to false. */
  pollingExponentialBackoff?: boolean;
  /** Optional pluggable logger for RPC simulation/submission traces. */
  logger?: SorobanIdentityLogger;
  /**
   * Expected contract deployment version string (e.g. `"0.1.0"`).
   *
   * When set and it does not match the SDK's own version constant the SDK
   * emits a `warn` log at construction time so operators can catch
   * contract/SDK mismatches before they cause runtime failures.
   */
  version?: string;
}

/** Per-call options that override the global config. */
export interface CallOptions {
  /** Override transaction timeout in seconds for this call only. */
  timeoutSeconds?: number;
  /**
   * Wall-clock timeout in milliseconds for this call. When the timeout
   * elapses the call rejects with `SorobanIdentityError` code `TIMEOUT`.
   * Overrides `SorobanIdentityConfig.defaultTimeoutMs` for this call only.
   */
  timeoutMs?: number;
  /** Override `maxRetries` for this call only (applies to `resolveDid`). */
  maxRetries?: number;
  /** Override `baseDelayMs` for this call only (applies to `resolveDid`). */
  baseDelayMs?: number;
  /** Override `backoffFactor` for this call only (applies to `resolveDid`). */
  backoffFactor?: number;
}

/** Returned by write methods — includes the prepared transaction and estimated fee. */
export interface WriteResult {
  /** Estimated fee in stroops (1 XLM = 10_000_000 stroops). */
  estimatedFee: number;
  /** Estimated fee in XLM (human-readable). */
  estimatedFeeXlm: string;
}

/**
 * Wrapper returned by all SDK write methods.
 *
 * `data` holds the method-specific return value (or `void`).
 * `txHash` is the on-chain transaction hash that callers can use for
 * auditing, linking, or querying the ledger directly.
 *
 * Read methods return `{ data: T }` without `txHash`.
 */
export type SorobanResponse<T> = { data: T; txHash: string };

export interface IdentityStorageStats {
  totalDids: number;
  activeDids: number;
}

export interface CredentialStorageStats {
  totalCredentials: number;
  revokedCredentials: number;
  activeCredentials: number;
}

export interface ReputationStorageStats {
  totalSubjects: number;
  totalScoreEntries: number;
}

/**
 * One page of results from a cursor-paginated list endpoint.
 *
 * `nextCursor` is `null` once the iterator is exhausted. While it is a number,
 * pass it back as the `cursor` argument on the next call to continue iteration.
 * Filtered queries may return fewer items than `limit` on a non-final page —
 * always advance while `nextCursor !== null`, not while `items.length === limit`.
 *
 * @see https://github.com/El-Chapo-Npm/Soroban-Identity/issues/248
 */
export interface Page<T> {
  items: T[];
  nextCursor: number | null;
}

/**
 * Options accepted by cursor-paginated list endpoints.
 *
 * @property cursor   Resume index from a prior page's `nextCursor`. Omit on the
 *                    first call to start from the beginning.
 * @property limit    Maximum items to return on this page. Clamped to 100 at
 *                    the contract layer; `0` is treated as "use the cap".
 */
export interface PaginationOptions extends CallOptions {
  cursor?: number;
  limit?: number;
}

/**
 * Extends {@link PaginationOptions} with a credential-type filter for
 * {@link CredentialClient.listCredentialsBySubject}. See issue #251.
 */
export interface CredentialListOptions extends PaginationOptions {
  credentialType?: CredentialType;
}

/** Contract ID field validated by {@link validateConfig} for a specific client. */
export type SorobanIdentityContractIdField =
  | "identityRegistryId"
  | "credentialManagerId"
  | "reputationId";

export interface ValidateConfigOptions {
  /** Contract ID that must be present and valid for the calling client. */
  contractIdField: SorobanIdentityContractIdField;
}

/**
 * Validates a {@link SorobanIdentityConfig} at client construction time so
 * misconfiguration fails fast with a descriptive error instead of a deep RPC failure.
 */
export function validateConfig(
  config: SorobanIdentityConfig,
  options: ValidateConfigOptions
): void {
  const rpcUrls = Array.isArray(config.rpcUrl) ? config.rpcUrl : [config.rpcUrl];
  if (rpcUrls.length === 0 || rpcUrls.some((url) => !url?.trim())) {
    throw new Error("rpcUrl is required");
  }

  if (!config.networkPassphrase?.trim()) {
    throw new Error("networkPassphrase is required");
  }

  const contractId = config[options.contractIdField];
  if (!contractId?.trim()) {
    throw new Error(`${options.contractIdField} is required`);
  }
  if (!StrKey.isValidContract(contractId)) {
    throw new Error(`${options.contractIdField} is not a valid contract ID`);
  }
}

export interface FeeEstimate {
  /** Base network fee in stroops. */
  baseFee: number;
  /** Soroban resource fee in stroops (after applying gas multiplier). */
  resourceFee: number;
  /** Total fee (baseFee + resourceFee) in stroops. */
  totalFee: number;
  /** Gas multiplier applied to the resource fee (1.0 = no adjustment, 1.5 = 50% increase). */
  gasMultiplier?: number;
  /** Original resource fee before multiplier was applied (in stroops). */
  originalResourceFee?: number;
}

export class SimulationError extends Error {
  constructor(message: string, public readonly raw?: unknown) {
    super(message);
    this.name = 'SimulationError';
  }
}

/**
 * Contract error codes introduced by the oracle, template, threshold-signature
 * and DID-resolver features (#1124–#1127).
 *
 * These mirror the numeric codes returned by the contracts so callers can map
 * a raw Soroban error to a stable SDK error code.
 */
export const CONTRACT_ERROR_CODES = {
  // Oracle (#1124)
  OracleNotFound: 4000,
  OracleInactive: 4001,
  OracleRequestNotFound: 4002,
  OracleRequestExpired: 4003,
  OracleResponseStale: 4004,
  OracleFeeMismatch: 4005,
  OracleSignatureInvalid: 4006,
  OracleNoFallback: 4007,
  // Credential templates (#1125)
  TemplateNotFound: 4100,
  TemplateInactive: 4101,
  TemplateVersionMismatch: 4102,
  TemplateValidationFailed: 4103,
  TemplateInheritanceCycle: 4104,
  TemplateListingNotFound: 4105,
  TemplateUsageFeeMismatch: 4106,
  // Threshold signatures (#1126)
  ThresholdNotMet: 4200,
  SignerSetNotFound: 4201,
  SignerNotAuthorized: 4202,
  SignerWeightInvalid: 4203,
  SignatureExpired: 4204,
  SignatureSchemeUnsupported: 4205,
  SignatureAggregationFailed: 4206,
  // DID resolver (#1127)
  DidMethodUnsupported: 4300,
  DidNotFound: 4301,
  DidResolutionFailed: 4302,
} as const;

export type ContractErrorCode = (typeof CONTRACT_ERROR_CODES)[keyof typeof CONTRACT_ERROR_CODES];

/** Reverse lookup: numeric contract error code → symbolic name. */
export const CONTRACT_ERROR_NAMES: Record<number, keyof typeof CONTRACT_ERROR_CODES> =
  Object.fromEntries(
    Object.entries(CONTRACT_ERROR_CODES).map(([name, code]) => [code, name])
  ) as Record<number, keyof typeof CONTRACT_ERROR_CODES>;

/** Map a raw numeric contract error code to its symbolic name, if known. */
export function contractErrorName(code: number): keyof typeof CONTRACT_ERROR_CODES | undefined {
  return CONTRACT_ERROR_NAMES[code];
}

/**
 * Minimal account information required to build an offline transaction.
 *
 * Obtain `sequence` from Horizon or Soroban RPC before disconnecting from the
 * network, then pass both fields to
 * {@link BaseClient.buildUnsignedTransaction}.
 */
export interface AccountInfo {
  /** Stellar public key (G-address) of the signing account. */
  publicKey: string;
  /**
   * Current account sequence number as a decimal string.
   *
   * Fetch this value once while online (e.g. via `server.getAccount(publicKey)`)
   * and cache it for offline transaction assembly.
   */
  sequence: string;
}

/**
 * Merkle tree structure used for batch credential verification (#1056).
 *
 * ## Tree layout
 *
 * Credential leaves are hashed with SHA-256 and inserted in the order they are
 * supplied to {@link MerkleTree}. The tree is built as a binary tree where:
 *
 * - Each **leaf** is `SHA-256(0x00 || credentialId)` — the `0x00` domain
 *   separator prevents second-preimage attacks where an internal node could be
 *   reinterpreted as a leaf.
 * - Each **internal node** is `SHA-256(0x01 || left || right)` — the `0x01`
 *   domain separator distinguishes internal nodes from leaves.
 * - When a level has an odd number of nodes, the last node is **duplicated**
 *   (paired with itself) before hashing, so every level has an even count.
 * - The **root** is the single node remaining at the top of the tree. An empty
 *   batch has a root of 32 zero bytes.
 *
 * ## Proofs
 *
 * A {@link MerkleProof} contains the sibling hashes on the path from the leaf
 * to the root, ordered from the bottom (closest to the leaf) upwards. Each
 * sibling carries a {@link MerkleProofSibling.index} that records the node's
 * position within its level; the verifier uses this to decide whether the
 * sibling is concatenated on the left or the right of the running hash.
 *
 * ## Incremental updates
 *
 * Appending a leaf to a batch updates only the rightmost path of the tree, so
 * the root can be recomputed in `O(log n)` hashes. The on-chain root is
 * replaced by submitting the new root with {@link MerkleBatchRoot.leafCount}
 * incremented; see {@link SubmitMerkleRootOptions}.
 */

/**
 * One sibling hash on the path from a credential leaf to the merkle root.
 *
 * `index` is the position of this node within its tree level. When
 * `index % 2 === 0` the sibling sits to the **left** of the running hash and is
 * concatenated first; when odd it sits to the **right**. `siblingOnLeft` is the
 * pre-computed boolean form of that check, provided so callers that serialise
 * proofs (e.g. to pass them to the contract) do not have to re-derive it.
 */
export interface MerkleProofSibling {
  /** Hex-encoded 32-byte sibling hash. */
  hash: string;
  /** Zero-based position of this node within its tree level. */
  index: number;
  /** `true` when this sibling is concatenated to the left of the running hash. */
  siblingOnLeft: boolean;
}

/**
 * Merkle inclusion proof for a single credential in a batch (#1056).
 *
 * Produced by {@link generateMerkleProof} and consumed by
 * {@link verifyMerkleProof}. The proof is self-contained: given the leaf hash,
 * the siblings and the expected root, verification requires no tree state.
 */
export interface MerkleProof {
  /** Hex-encoded 32-byte hash of the credential leaf being proven. */
  leaf: string;
  /**
   * Sibling hashes from the leaf level upwards. The first entry is the sibling
   * of the leaf itself; the last entry is the sibling of the child of the root.
   */
  siblings: MerkleProofSibling[];
  /** Zero-based index of the leaf within the batch. */
  leafIndex: number;
  /** Total number of leaves in the batch the proof was generated from. */
  leafCount: number;
  /** Hex-encoded 32-byte merkle root the proof resolves to. */
  root: string;
}

/**
 * On-chain merkle root for a batch of credentials (#1056).
 *
 * Stored by the credential-manager contract so a verifier only needs the root
 * (32 bytes) plus a proof (`O(log n)` hashes) instead of every credential in
 * the batch. This keeps verification gas cost logarithmic in the batch size.
 */
export interface MerkleBatchRoot {
  /** Identifier of the batch this root commits to. */
  batchId: string;
  /** Hex-encoded 32-byte merkle root. */
  root: string;
  /** Number of credential leaves committed to by `root`. */
  leafCount: number;
  /** Unix timestamp (seconds) when the root was last updated on-chain. */
  updatedAt: number;
}

/**
 * Options for {@link generateMerkleProof} / {@link generateMerkleProofs}.
 */
export interface MerkleProofOptions {
  /**
   * Hash function used to build the tree. Defaults to `"sha256"`, the only
   * algorithm supported by the on-chain verifier.
   */
  algorithm?: "sha256";
  /**
   * When `true`, proofs are generated for every leaf in the batch rather than
   * a single leaf. Used by {@link generateMerkleProofs}.
   */
  allLeaves?: boolean;
}

/**
 * Options for submitting a merkle root to the credential-manager contract.
 *
 * Extends {@link CallOptions} so callers can override the transaction timeout
 * for large batches.
 */
export interface SubmitMerkleRootOptions extends CallOptions {
  /**
   * Batch identifier to associate with the root. When omitted the contract
   * derives one from the issuer address and the current ledger sequence.
   */
  batchId?: string;
  /**
   * When `true`, the contract treats the submission as an incremental update:
   * the existing root for `batchId` is replaced and `leafCount` is expected to
   * be greater than the stored value. Defaults to `false` (full replacement).
   */
  incremental?: boolean;
  /**
   * Expected leaf count after the update. The contract rejects the submission
   * when this does not match the recomputed tree size, guarding against
   * truncated batches.
   */
  expectedLeafCount?: number;
}

/**
 * Options for verifying a merkle proof against an on-chain root.
 */
export interface VerifyMerkleProofOptions extends CallOptions {
  /**
   * Expected merkle root. When omitted the SDK fetches the stored root for
   * {@link MerkleBatchRoot.batchId} from the contract before verifying.
   */
  root?: string;
  /** Batch identifier whose stored root should be used when `root` is omitted. */
  batchId?: string;
}

/* -------------------------------------------------------------------------- */
/* Oracle integration (#1124)                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Configuration for a single oracle node the SDK may query for off-chain data.
 *
 * Mirrors the oracle-registry contract's `OracleConfig` contracttype. The
 * `address` is the Stellar account that signs oracle responses; `fee` is the
 * amount (in stroops) the oracle charges per request.
 */
export interface OracleConfig {
  /** Unique oracle identifier (hex-encoded 32 bytes). */
  oracleId: string;
  /** Stellar address of the oracle node that signs responses. */
  address: string;
  /** Human-readable oracle name. */
  name: string;
  /** Fee charged per request, in stroops. */
  fee: number;
  /**
   * Maximum age (seconds) of a response before it is considered stale.
   * `0` disables staleness checks for this oracle.
   */
  maxStaleness: number;
  /** `false` once the oracle has been deregistered. */
  active: boolean;
  /**
   * Fallback oracle IDs consulted in order when this oracle fails or returns
   * stale data. Empty when no fallbacks are configured.
   */
  fallbackOracles: string[];
}

/**
 * Schema describing the shape of a data feed served by an oracle.
 *
 * The `fields` map names each field and its type so callers can validate
 * decoded oracle payloads before trusting them.
 */
export interface DataFeedSchema {
  /** Unique feed identifier (hex-encoded 32 bytes). */
  feedId: string;
  /** Oracle that serves this feed. */
  oracleId: string;
  /** Schema version; incremented when the field layout changes. */
  version: number;
  /** Field name → type descriptor (e.g. `"string"`, `"u32"`, `"bool"`). */
  fields: Record<string, string>;
  /** Unix timestamp (seconds) when the schema was registered. */
  registeredAt: number;
}

/** Lifecycle state of an {@link OracleRequest}. */
export type OracleRequestStatus = "Pending" | "Fulfilled" | "Failed" | "Expired";

/**
 * An outstanding or completed request for off-chain data (#1124).
 *
 * Created by the SDK when calling the oracle request function; the oracle
 * later fulfils it by submitting a signed {@link OracleResponse}.
 */
export interface OracleRequest {
  /** Unique request identifier (hex-encoded 32 bytes). */
  requestId: string;
  /** Oracle the request was sent to. */
  oracleId: string;
  /** Data feed the request targets. */
  feedId: string;
  /** Address that submitted the request (pays the oracle fee). */
  requester: string;
  /** Opaque request payload, hex-encoded. */
  payload: string;
  /** Unix timestamp (seconds) when the request was created. */
  createdAt: number;
  /** Unix timestamp (seconds) after which the request expires. */
  expiresAt: number;
  /** Current lifecycle state. */
  status: OracleRequestStatus;
}

/**
 * A signed response from an oracle, returned by
 * {@link OracleClient.getResponse} once a request is fulfilled.
 */
export interface OracleResponse {
  /** Request this response fulfils. */
  requestId: string;
  /** Oracle that produced the response. */
  oracleId: string;
  /** Decoded feed data, keyed by field name. */
  data: Record<string, string>;
  /** Hex-encoded signature over the response payload. */
  signature: string;
  /** Unix timestamp (seconds) the oracle reports for the data. */
  observedAt: number;
  /** Unix timestamp (seconds) the response was recorded on-chain. */
  fulfilledAt: number;
  /**
   * `true` when `observedAt` is older than the oracle's `maxStaleness` at the
   * time the response was read. Stale responses must not be trusted.
   */
  stale: boolean;
}

/* -------------------------------------------------------------------------- */
/* Credential templates (#1125)                                               */
/* -------------------------------------------------------------------------- */

/**
 * A reusable credential template stored on-chain (#1125).
 *
 * Templates define the credential type, default claims and validation rules
 * that issuers can reuse when minting credentials. Templates are versioned and
 * may inherit from a parent template.
 */
export interface CredentialTemplate {
  /** Unique template identifier (hex-encoded 32 bytes). */
  templateId: string;
  /** Issuer that registered the template. */
  issuer: string;
  /** Credential type this template produces. */
  credentialType: CredentialType;
  /** Human-readable template name. */
  name: string;
  /** Default claims applied to credentials minted from this template. */
  defaultClaims: Record<string, string>;
  /** Validation rules keyed by claim name (e.g. `"required"`, `"maxLength:64"`). */
  validationRules: Record<string, string>;
  /** Monotonically increasing version; starts at 1. */
  version: number;
  /** Parent template ID when this template inherits from another, else `null`. */
  parentTemplateId: string | null;
  /** Unix timestamp (seconds) when the template was registered. */
  createdAt: number;
  /** Unix timestamp (seconds) of the last version bump. */
  updatedAt: number;
  /** `false` once the template has been deprecated. */
  active: boolean;
}

/**
 * A template listed for sale on the template marketplace (#1125).
 */
export interface TemplateListing {
  /** Template being sold. */
  templateId: string;
  /** Address of the seller (must be the template issuer). */
  seller: string;
  /** Usage fee per mint, in stroops. `0` means free. */
  usageFee: number;
  /** Unix timestamp (seconds) when the listing was created. */
  listedAt: number;
  /** `false` once the listing has been withdrawn. */
  active: boolean;
}

/* -------------------------------------------------------------------------- */
/* Threshold signatures (#1126)                                               */
/* -------------------------------------------------------------------------- */

/**
 * Signature scheme supported by the threshold-signature verifier (#1126).
 *
 * The values are the contract's variant names and are part of the wire format:
 * never rename or reorder them.
 */
export const SignatureScheme = {
  Ed25519: "Ed25519",
  Secp256k1: "Secp256k1",
  Secp256r1: "Secp256r1",
} as const;

export type SignatureScheme = (typeof SignatureScheme)[keyof typeof SignatureScheme];

/** Every supported signature scheme, in the contract's declaration order. */
export const SIGNATURE_SCHEMES: readonly SignatureScheme[] = [
  SignatureScheme.Ed25519,
  SignatureScheme.Secp256k1,
  SignatureScheme.Secp256r1,
];

/** True when `value` is a supported {@link SignatureScheme}. */
export function isSignatureScheme(value: unknown): value is SignatureScheme {
  return typeof value === "string" && (SIGNATURE_SCHEMES as readonly string[]).includes(value);
}

/**
 * A weighted signer in a {@link SignerSet}.
 */
export interface Signer {
  /** Stellar address of the signer. */
  address: string;
  /** Relative weight of this signer's signature. Must be > 0. */
  weight: number;
  /** Signature scheme this signer uses. */
  scheme: SignatureScheme;
}

/**
 * A dynamic set of weighted signers with a threshold (#1126).
 *
 * A payload is valid when the sum of weights of the signers that produced a
 * valid signature is greater than or equal to `threshold`.
 */
export interface SignerSet {
  /** Unique signer-set identifier (hex-encoded 32 bytes). */
  signerSetId: string;
  /** Weighted signers. */
  signers: Signer[];
  /** Minimum total weight required to authorise an operation. */
  threshold: number;
  /** Unix timestamp (seconds) after which signatures are rejected. `0` = no expiry. */
  expiresAt: number;
}

/**
 * A payload signed by one or more signers under a {@link SignerSet} (#1126).
 */
export interface SignedPayload {
  /** Signer set the signatures are validated against. */
  signerSetId: string;
  /** Hex-encoded payload that was signed. */
  payload: string;
  /** Individual signatures, one per signer. */
  signatures: Array<{
    /** Address of the signer that produced this signature. */
    signer: string;
    /** Hex-encoded signature bytes. */
    signature: string;
    /** Scheme used to produce the signature. */
    scheme: SignatureScheme;
  }>;
  /** Unix timestamp (seconds) when the payload was signed. */
  signedAt: number;
}

/* -------------------------------------------------------------------------- */
/* DID resolver (#1127)                                                       */
/* -------------------------------------------------------------------------- */

/**
 * DID method supported by the universal resolver (#1127).
 *
 * `Stellar` is the native method; the others are resolved via adapters.
 */
export const DidMethod = {
  Stellar: "Stellar",
  Key: "Key",
  Web: "Web",
  Ethr: "Ethr",
} as const;

export type DidMethod = (typeof DidMethod)[keyof typeof DidMethod];

/** Every supported DID method, in the contract's declaration order. */
export const DID_METHODS: readonly DidMethod[] = [
  DidMethod.Stellar,
  DidMethod.Key,
  DidMethod.Web,
  DidMethod.Ethr,
];

/** True when `value` is a supported {@link DidMethod}. */
export function isDidMethod(value: unknown): value is DidMethod {
  return typeof value === "string" && (DID_METHODS as readonly string[]).includes(value);
}

/**
 * A DID document resolved by the universal resolver (#1127).
 *
 * Extends {@link DidDocument} with the method that produced it and resolution
 * metadata so callers can tell which adapter answered and whether the result
 * came from cache.
 */
export interface ResolvedDidDocument extends DidDocument {
  /** DID method that resolved this document. */
  method: DidMethod;
  /** Unix timestamp (seconds) when the document was resolved. */
  resolvedAt: number;
  /** `true` when the document was served from a local cache. */
  fromCache: boolean;
}
