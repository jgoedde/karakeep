import { z } from "zod";

/**
 * A cookie in the shape Playwright's `BrowserContext.addCookies` accepts.
 */
const cookieSchema = z.object({
  name: z.string(),
  value: z.string(),
  domain: z.string().optional(),
  path: z.string().optional(),
  expires: z.number().optional(),
  httpOnly: z.boolean().optional(),
  secure: z.boolean().optional(),
  sameSite: z.enum(["Strict", "Lax", "None"]).optional(),
});

export type Cookie = z.infer<typeof cookieSchema>;

const cookiesSchema = z.array(cookieSchema);

/**
 * Parses the contents of a cookie file. JSON arrays of Playwright-shaped
 * cookies and Netscape `cookies.txt` files are supported; the format is
 * detected from the content.
 */
export function parseCookieFile(rawContent: string): Cookie[] {
  const content = rawContent.replace(/^\uFEFF/, "");
  if (content.trimStart().startsWith("[")) {
    return cookiesSchema.parse(JSON.parse(content));
  }
  return parseNetscapeCookies(content);
}

const HTTP_ONLY_PREFIX = "#HttpOnly_";

function parseNetscapeCookies(content: string): Cookie[] {
  const cookies: Cookie[] = [];
  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    if (rawLine.trim() === "") {
      continue;
    }
    const httpOnly = rawLine.startsWith(HTTP_ONLY_PREFIX);
    if (rawLine.startsWith("#") && !httpOnly) {
      continue;
    }
    const line = httpOnly ? rawLine.slice(HTTP_ONLY_PREFIX.length) : rawLine;
    const fields = line.split("\t");
    if (fields.length < 7) {
      throw new Error(
        `Invalid cookies.txt line ${index + 1}: expected 7 tab-separated fields`,
      );
    }
    const [domain, includeSubdomains, path, secure, expiry, name] = fields;
    // The value is everything after the 6th tab, so values with tabs survive.
    const value = fields.slice(6).join("\t");
    // Playwright treats a leading dot as "also match subdomains".
    const hostOnlyDomain = domain.replace(/^\./, "");
    const cookie: Cookie = {
      name,
      value,
      domain:
        includeSubdomains === "TRUE" ? `.${hostOnlyDomain}` : hostOnlyDomain,
      path,
      httpOnly,
      secure: secure === "TRUE",
    };
    // An expiry of 0 marks a session cookie.
    const expires = expiry.trim() === "" ? NaN : Number(expiry);
    if (!Number.isFinite(expires)) {
      throw new Error(
        `Invalid cookies.txt line ${index + 1}: expiry must be a number`,
      );
    }
    if (expires !== 0) {
      cookie.expires = expires;
    }
    cookies.push(cookie);
  }
  return cookies;
}
