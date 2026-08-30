import { createFileRoute } from "@tanstack/react-router";
import { handleTeamOidcLogout } from "@/lib/team/oidc-http";

export const Route = createFileRoute("/api/team/oidc/logout")({
  server: {
    handlers: {
      POST: ({ request }) => handleTeamOidcLogout(request),
    },
  },
});
