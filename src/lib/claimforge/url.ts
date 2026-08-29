import { isPathIdentifier, isPrefixedId, isSlugId, isUlid, isUuid } from "./ids.ts";

export function templatize(path: string): string {
  return path
    .split("/")
    .map((seg) => {
      if (!seg) return seg;
      if (!isPathIdentifier(seg)) return seg;
      if (/^[0-9]+$/.test(seg)) return "{id}";
      if (isUuid(seg)) return "{uuid}";
      if (isUlid(seg)) return "{ulid}";
      if (isPrefixedId(seg)) return "{id}";
      if (isSlugId(seg)) return "{slug}";
      if (/^[0-9a-f]{12,}$/i.test(seg)) return "{hex}";
      if (/^[\w.+-]+@[\w.-]+$/.test(seg)) return "{email}";
      return "{id}";
    })
    .join("/");
}
