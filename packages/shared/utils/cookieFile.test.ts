import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { parseCookieFile } from "./cookieFile";

describe("parseCookieFile", () => {
  describe("JSON format", () => {
    it("passes a valid JSON cookie array through unchanged", () => {
      const cookies = [
        {
          name: "session",
          value: "abc",
          domain: ".example.com",
          path: "/",
          expires: 1700000000,
          httpOnly: true,
          secure: true,
          sameSite: "Lax",
        },
        { name: "minimal", value: "x" },
      ];
      expect(parseCookieFile(JSON.stringify(cookies))).toEqual(cookies);
    });

    it("throws a zod error when the JSON does not match the cookie schema", () => {
      expect(() =>
        parseCookieFile(JSON.stringify([{ name: "a", value: 1 }])),
      ).toThrow(ZodError);
    });

    it("detects JSON after leading whitespace", () => {
      expect(parseCookieFile('\n  \t[{"name":"a","value":"b"}]')).toEqual([
        { name: "a", value: "b" },
      ]);
    });
  });

  describe("Netscape cookies.txt format", () => {
    it("maps all fields of a cookie line", () => {
      expect(
        parseCookieFile(
          "www.example.com\tFALSE\t/account\tTRUE\t1700000000\tsid\tabc123",
        ),
      ).toEqual([
        {
          name: "sid",
          value: "abc123",
          domain: "www.example.com",
          path: "/account",
          expires: 1700000000,
          httpOnly: false,
          secure: true,
        },
      ]);
    });

    it("adds a leading dot to the domain when includeSubdomains is TRUE", () => {
      const [cookie] = parseCookieFile(
        "example.com\tTRUE\t/\tFALSE\t1700000000\ta\tb",
      );
      expect(cookie.domain).toBe(".example.com");
    });

    it("keeps an existing leading dot when includeSubdomains is TRUE", () => {
      const [cookie] = parseCookieFile(
        ".example.com\tTRUE\t/\tFALSE\t1700000000\ta\tb",
      );
      expect(cookie.domain).toBe(".example.com");
    });

    it("strips the leading dot when includeSubdomains is FALSE", () => {
      const [cookie] = parseCookieFile(
        ".example.com\tFALSE\t/\tFALSE\t1700000000\ta\tb",
      );
      expect(cookie.domain).toBe("example.com");
    });

    it("treats #HttpOnly_ lines as HttpOnly cookies and strips the prefix", () => {
      expect(
        parseCookieFile(
          "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1700000000\tsid\tabc",
        ),
      ).toEqual([
        {
          name: "sid",
          value: "abc",
          domain: ".example.com",
          path: "/",
          expires: 1700000000,
          httpOnly: true,
          secure: true,
        },
      ]);
    });

    it("omits expires for session cookies with expiry 0", () => {
      const [cookie] = parseCookieFile("example.com\tFALSE\t/\tFALSE\t0\ta\tb");
      expect(cookie).not.toHaveProperty("expires");
    });

    it("ignores the header comment and blank lines", () => {
      const content = [
        "# Netscape HTTP Cookie File",
        "# https://curl.se/docs/http-cookies.html",
        "",
        "example.com\tFALSE\t/\tFALSE\t0\tfirst\t1",
        "   ",
        "example.org\tFALSE\t/\tFALSE\t0\tsecond\t2",
        "",
      ].join("\n");
      expect(parseCookieFile(content).map((c) => c.name)).toEqual([
        "first",
        "second",
      ]);
    });

    it("ignores a leading UTF-8 byte order mark", () => {
      const content =
        "\uFEFF# Netscape HTTP Cookie File\nexample.com\tFALSE\t/\tFALSE\t0\ta\tb\n";
      expect(parseCookieFile(content).map((c) => c.name)).toEqual(["a"]);
    });

    it("returns no cookies for a file with only comments", () => {
      expect(
        parseCookieFile("# Netscape HTTP Cookie File\n# nothing here\n"),
      ).toEqual([]);
    });

    it("parses CRLF line endings the same as LF", () => {
      const lines = [
        "# Netscape HTTP Cookie File",
        "",
        "example.com\tTRUE\t/\tTRUE\t1700000000\ta\tb",
        "#HttpOnly_example.org\tFALSE\t/\tFALSE\t0\tc\td",
      ];
      const crlf = parseCookieFile(lines.join("\r\n"));
      expect(crlf).toEqual(parseCookieFile(lines.join("\n")));
      expect(crlf[0].value).toBe("b");
      expect(crlf[1].value).toBe("d");
    });

    it("preserves tab characters inside the value", () => {
      const [cookie] = parseCookieFile(
        "example.com\tFALSE\t/\tFALSE\t0\ta\tpart1\tpart2\tpart3",
      );
      expect(cookie.value).toBe("part1\tpart2\tpart3");
    });

    it.each([
      ["non-numeric", "abc"],
      ["empty", ""],
    ])("throws naming the line number when the expiry is %s", (_, expiry) => {
      const content = [
        "# Netscape HTTP Cookie File",
        `example.com\tFALSE\t/\tFALSE\t${expiry}\ta\tb`,
      ].join("\n");
      expect(() => parseCookieFile(content)).toThrow(
        "Invalid cookies.txt line 2: ",
      );
    });

    it("throws naming the 1-based line number of a malformed line", () => {
      const content = [
        "# Netscape HTTP Cookie File",
        "",
        "example.com\tFALSE\t/\tFALSE\t0\ta\tb",
        "example.com\tFALSE\t/\tFALSE\t0\tmissing-value",
      ].join("\n");
      expect(() => parseCookieFile(content)).toThrow(
        "Invalid cookies.txt line 4: expected 7 tab-separated fields",
      );
    });
  });
});
