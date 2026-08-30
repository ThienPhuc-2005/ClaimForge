import { createFileRoute } from "@tanstack/react-router";
import { handleTeamOidcLogin } from "@/lib/team/oidc-http";

export const Route = createFileRoute("/api/team/oidc/login")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamOidcLogin(request),
    },
  },
});
