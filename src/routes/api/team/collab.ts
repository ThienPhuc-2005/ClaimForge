import { createFileRoute } from "@tanstack/react-router";
import { handleTeamCollabGet, handleTeamCollabPatch } from "@/lib/team/collab-http";

export const Route = createFileRoute("/api/team/collab")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamCollabGet(request),
      PATCH: ({ request }) => handleTeamCollabPatch(request),
    },
  },
});
