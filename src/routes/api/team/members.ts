import { createFileRoute } from "@tanstack/react-router";
import {
  handleTeamMembersDelete,
  handleTeamMembersGet,
  handleTeamMembersPatch,
  handleTeamMembersPost,
} from "@/lib/team/rbac-http";

export const Route = createFileRoute("/api/team/members")({
  server: {
    handlers: {
      GET: ({ request }) => handleTeamMembersGet(request),
      POST: ({ request }) => handleTeamMembersPost(request),
      PATCH: ({ request }) => handleTeamMembersPatch(request),
      DELETE: ({ request }) => handleTeamMembersDelete(request),
    },
  },
});
