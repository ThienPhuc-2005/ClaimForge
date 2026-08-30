import { createFileRoute } from "@tanstack/react-router";
import { handleTeamSession } from "@/lib/team/oidc-http";

export const Route = createFileRoute("/api/team/session")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamSession(request),
    },
  },
});
