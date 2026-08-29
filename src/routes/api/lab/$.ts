import { createFileRoute } from "@tanstack/react-router";
import { handleLabRequest } from "@/lib/lab/engine";

async function lab({ request }: { request: Request }) {
  return handleLabRequest(request);
}

export const Route = createFileRoute("/api/lab/$")({
  server: {
    handlers: {
      GET: lab,
      POST: lab,
      PUT: lab,
      PATCH: lab,
      DELETE: lab,
      OPTIONS: lab,
    },
  },
});
