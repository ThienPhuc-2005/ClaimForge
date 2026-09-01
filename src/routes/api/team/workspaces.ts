import { createFileRoute } from "@tanstack/react-router";
import {
  handleTeamWorkspacesDelete,
  handleTeamWorkspacesGet,
  handleTeamWorkspacesPost,
} from "@/lib/team/collab-http";

export const Route = createFileRoute("/api/team/workspaces")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamWorkspacesGet(request),
      POST: ({ request }) => handleTeamWorkspacesPost(request),
      DELETE: ({ request }) => handleTeamWorkspacesDelete(request),
    },
  },
});
