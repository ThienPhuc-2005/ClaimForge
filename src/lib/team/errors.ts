export class TeamError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "TeamError";
    this.code = code;
  }
}

/** Unverified context or caller-supplied tenant_id. */
export class TeamIsolationError extends TeamError {
  constructor(message: string) {
    super("isolation", message);
    this.name = "TeamIsolationError";
  }
}

/** Missing and cross-tenant resources share this type (no existence leak). */
export class TeamNotFoundError extends TeamError {
  constructor(message = "not found") {
    super("not_found", message);
    this.name = "TeamNotFoundError";
  }
}

export class TeamAmbiguousError extends TeamError {
  constructor(message: string) {
    super("ambiguous", message);
    this.name = "TeamAmbiguousError";
  }
}

export class TeamBootstrapError extends TeamError {
  constructor(message: string) {
    super("bootstrap", message);
    this.name = "TeamBootstrapError";
  }
}

export class TeamPersistError extends TeamError {
  constructor(message: string) {
    super("persist", message);
    this.name = "TeamPersistError";
  }
}

export class TeamValidationError extends TeamError {
  constructor(message: string) {
    super("validation", message);
    this.name = "TeamValidationError";
  }
}
