#!/usr/bin/env node
/**
 * Operator-only first-tenant bootstrap. Not an HTTP endpoint.
 * Secret comes from CLAIMFORGE_TEAM_BOOTSTRAP_SECRET, never argv.
 */
import { runTeamBootstrap } from "../src/lib/team/bootstrap-cli.ts";

const code = await runTeamBootstrap(process.argv.slice(2), process.env);
process.exitCode = code;
