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
  | "PUBLIC_OR_SHARED_ROUTE";

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
