import { createFileRoute } from "@tanstack/react-router";
import { handleTeamAuditGet } from "@/lib/team/audit-http";

export const Route = createFileRoute("/api/team/audit")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamAuditGet(request),
    },
  },
});
