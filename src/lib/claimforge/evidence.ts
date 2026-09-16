import type { ActorId, CapturedRequest, FindingConfidence } from "./types.ts";
import { RULE_ID_BOLA_CROSS_ACTOR, RULE_VERSION } from "./versions.ts";

export type OwnershipSourceKind =
  | "response-field"
  | "inventory-response"
  | "analyst-actor-map"
  | "verified-jwt"
  | "request-body"
  | "request-query"
  | "request-path"
  | "unverified-jwt"
  | "none";

export type ReasonCode =
  | "CROSS_ACTOR_2XX"
  | "SERVER_OWNERSHIP_PROOF"
  | "MISSING_TRUSTED_OWNERSHIP"
  | "MISSING_CROSS_ACTOR_ACCESS"
  | "UNTRUSTED_JWT_IDENTITY"
  | "REQUEST_BODY_OWNERSHIP_REJECTED"
  | "REQUEST_QUERY_OWNERSHIP_REJECTED"
  | "REQUEST_PATH_OWNERSHIP_REJECTED"
  | "PUBLIC_OR_SHARED_ROUTE"
  | "LOGOUT_CREDENTIAL_REPLAYED"
  | "LOGOUT_UNAUTHENTICATED"
  | "LOGOUT_PUBLIC_ROUTE"
  | "SIBLING_SESSION_INTACT"
  | "JWT_ALG_NONE"
  | "JWT_UNSIGNED"
  | "JWT_KEY_INJECTION"
  | "JWT_PRIVILEGED_ROLE"
  | "JWT_LIFETIME"
  | "JWT_ISS_MISSING"
  | "JWT_AUD_MISSING"
  | "JWT_SUB_MISMATCH"
  | "COOKIE_MISSING_HTTPONLY"
  | "COOKIE_MISSING_SECURE"
  | "COOKIE_MISSING_SAMESITE"
  | "COOKIE_SAMESITE_NONE_INSECURE"
  | "COOKIE_LONG_MAX_AGE"
  | "TOKEN_IN_QUERY"
  | "HTTP_BASIC"
  | "CORS_REFLECTED_CREDENTIALS"
  | "CORS_STAR_NO_CREDENTIALS"
  | "MASS_ASSIGN_HONORED"
  | "ROLE_ESCALATION"
  | "SECRET_IN_CAPTURE"
  | "STACK_TRACE_LEAK"
  | "BFLA_PRIVILEGED_FUNCTION"
  | "BFLA_LOW_PRIV_ACTOR_2XX"
  | "BFLA_ROLE_VERIFIED"
  | "BFLA_ENFORCEMENT_OBSERVED"
  | "MISSING_VERIFIED_ROLE"
  | "MISSING_FUNCTION_PRIVILEGE_PROOF"
  | "CSRF_STATE_CHANGE_COOKIE_AUTH"
  | "CSRF_NO_TOKEN"
  | "CSRF_SAMESITE_NONE"
  | "CSRF_SAMESITE_DEFAULT_LAX"
  | "REFRESH_TOKEN_REUSE"
  | "REFRESH_TOKEN_REPLAYED"
  | "REFRESH_ROTATION_OBSERVED"
  | "SPEC_ENDPOINT_UNTESTED"
  | "SPEC_SHADOW_ENDPOINT"
  | "OPEN_REDIRECT_REFLECTED"
  | "OPEN_REDIRECT_DANGEROUS_SCHEME"
  | "OPEN_REDIRECT_PARAM_UNVERIFIED"
  | "CAPTURE_TRUNCATED"
  | "CAPTURE_HEURISTIC_ONLY"
  | "IMPACT_NOT_PROVEN"
  | "NO_FINDING";

export interface CanonicalEvidence {
  ruleId: string;
  ruleVersion: string;
  policyVersion: string;
  actor: ActorId;
  identityProvenance: OwnershipSourceKind[];
  direction: "request" | "response";
  endpoint: string;
  ownershipSource: OwnershipSourceKind;
  ownershipTrusted: boolean;
  ownershipReason: string;
  captureIds: string[];
  reasonCodes: ReasonCode[];
}

export function bolaConclusion(args: {
  crossActorOk: boolean;
  ownershipTrusted: boolean;
  publicOrShared: boolean;
}): FindingConfidence {
  if (args.publicOrShared) return "observation";
  if (args.crossActorOk && args.ownershipTrusted) return "confirmed";
  if (args.crossActorOk && !args.ownershipTrusted) return "suspicion";
  return "observation";
}

export function bolaEvidence(args: {
  policyVersion: string;
  actor: ActorId;
  endpoint: string;
  ownershipSource: OwnershipSourceKind;
  ownershipTrusted: boolean;
  ownershipReason: string;
  identityProvenance: OwnershipSourceKind[];
  captureIds: string[];
  reasonCodes: ReasonCode[];
}): CanonicalEvidence {
  return {
    ruleId: RULE_ID_BOLA_CROSS_ACTOR,
    ruleVersion: RULE_VERSION,
    policyVersion: args.policyVersion,
    actor: args.actor,
    identityProvenance: args.identityProvenance,
    direction: "response",
    endpoint: args.endpoint,
    ownershipSource: args.ownershipSource,
    ownershipTrusted: args.ownershipTrusted,
    ownershipReason: args.ownershipReason,
    captureIds: args.captureIds,
    reasonCodes: args.reasonCodes,
  };
}

export function captureRef(req: CapturedRequest): string {
  return req.id;
}
