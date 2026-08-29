export function templatize(path: string): string {
  return path
    .split("/")
    .map((seg) => {
      if (!seg) return seg;
      if (/^[0-9]+$/.test(seg)) return "{id}";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{uuid}";
      if (/^[0-9a-f]{16,}$/i.test(seg)) return "{hex}";
      if (/^[\w.+-]+@[\w.-]+$/.test(seg)) return "{email}";
      return seg;
    })
    .join("/");
}
