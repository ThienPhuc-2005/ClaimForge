import { createFileRoute } from "@tanstack/react-router";
import { handleTeamOidcCallback } from "@/lib/team/oidc-http";

export const Route = createFileRoute("/api/team/oidc/callback")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamOidcCallback(request),
    },
  },
});
