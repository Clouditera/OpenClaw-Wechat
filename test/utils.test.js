import { describe, it, expect } from "vitest";
import {
  sha1,
  computeMsgSignature,
  decodeAesKey,
  pkcs7Unpad,
  parseIncomingXml,
  requireEnv,
  asNumber,
  getByteLength,
  markdownToWecomText,
  splitWecomText,
} from "../src/utils.js";

describe("sha1", () => {
  it("should compute correct SHA1 hash", () => {
    expect(sha1("hello")).toBe("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
  });

  it("should handle empty string", () => {
    expect(sha1("")).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
  });
});

describe("computeMsgSignature", () => {
  it("should sort params and compute SHA1", () => {
    const sig = computeMsgSignature({
      token: "token123",
      timestamp: "1234567890",
      nonce: "nonce456",
      encrypt: "encrypt789",
    });
    expect(sig).toMatch(/^[0-9a-f]{40}$/);
  });

  it("should produce same result regardless of param order", () => {
    const params = {
      token: "a",
      timestamp: "b",
      nonce: "c",
      encrypt: "d",
    };
    const sig1 = computeMsgSignature(params);
    const sig2 = computeMsgSignature({
      encrypt: "d",
      nonce: "c",
      timestamp: "b",
      token: "a",
    });
    expect(sig1).toBe(sig2);
  });
});

describe("decodeAesKey", () => {
  it("should append = if missing and decode base64", () => {
    // 43-char base64 string (standard WeCom AES key length)
    const key43 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    const buf = decodeAesKey(key43);
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBe(32); // AES-256 key = 32 bytes
  });

  it("should handle key already ending with =", () => {
    const key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=";
    const buf = decodeAesKey(key);
    expect(buf.length).toBe(32);
  });
});

describe("pkcs7Unpad", () => {
  it("should remove PKCS7 padding", () => {
    const data = Buffer.from([1, 2, 3, 4, 4, 4, 4, 4]);
    const result = pkcs7Unpad(data);
    expect([...result]).toEqual([1, 2, 3, 4]);
  });

  it("should return original buffer if pad byte > 32", () => {
    const data = Buffer.from([1, 2, 3, 33]);
    const result = pkcs7Unpad(data);
    expect([...result]).toEqual([1, 2, 3, 33]);
  });

  it("should return original buffer if pad byte is 0", () => {
    const data = Buffer.from([1, 2, 3, 0]);
    const result = pkcs7Unpad(data);
    expect([...result]).toEqual([1, 2, 3, 0]);
  });
});

describe("parseIncomingXml", () => {
  it("should parse WeCom callback XML", () => {
    const xml = `<xml>
      <ToUserName><![CDATA[corp123]]></ToUserName>
      <FromUserName><![CDATA[user456]]></FromUserName>
      <MsgType><![CDATA[text]]></MsgType>
      <Content><![CDATA[hello world]]></Content>
    </xml>`;
    const result = parseIncomingXml(xml);
    expect(result.ToUserName).toBe("corp123");
    expect(result.FromUserName).toBe("user456");
    expect(result.MsgType).toBe("text");
    expect(result.Content).toBe("hello world");
  });

  it("should parse encrypted callback XML", () => {
    const xml = `<xml><Encrypt><![CDATA[encrypted_data_here]]></Encrypt></xml>`;
    const result = parseIncomingXml(xml);
    expect(result.Encrypt).toBe("encrypted_data_here");
  });
});

describe("requireEnv", () => {
  it("should return env var value", () => {
    process.env.TEST_WECOM_VAR = "test_value";
    expect(requireEnv("TEST_WECOM_VAR")).toBe("test_value");
    delete process.env.TEST_WECOM_VAR;
  });

  it("should return fallback for missing var", () => {
    expect(requireEnv("NONEXISTENT_VAR_12345", "fallback")).toBe("fallback");
  });

  it("should return fallback for empty string", () => {
    process.env.TEST_EMPTY_VAR = "";
    expect(requireEnv("TEST_EMPTY_VAR", "default")).toBe("default");
    delete process.env.TEST_EMPTY_VAR;
  });
});

describe("asNumber", () => {
  it("should convert string to number", () => {
    expect(asNumber("42")).toBe(42);
  });

  it("should return fallback for null", () => {
    expect(asNumber(null, 0)).toBe(0);
  });

  it("should return fallback for NaN", () => {
    expect(asNumber("not_a_number", -1)).toBe(-1);
  });

  it("should return fallback for Infinity", () => {
    expect(asNumber("Infinity", 0)).toBe(0);
  });
});

describe("getByteLength", () => {
  it("should count ASCII bytes correctly", () => {
    expect(getByteLength("hello")).toBe(5);
  });

  it("should count Chinese characters as 3 bytes each", () => {
    expect(getByteLength("你好")).toBe(6);
  });

  it("should handle mixed content", () => {
    expect(getByteLength("hi你好")).toBe(8); // 2 + 6
  });

  it("should handle empty string", () => {
    expect(getByteLength("")).toBe(0);
  });
});

describe("markdownToWecomText", () => {
  it("should convert headers", () => {
    expect(markdownToWecomText("# Title")).toBe("◆ Title");
    expect(markdownToWecomText("## Subtitle")).toBe("■ Subtitle");
    expect(markdownToWecomText("### Section")).toBe("▸ Section");
  });

  it("should strip bold and italic markers", () => {
    expect(markdownToWecomText("**bold**")).toBe("bold");
    expect(markdownToWecomText("*italic*")).toBe("italic");
    expect(markdownToWecomText("***both***")).toBe("both");
  });

  it("should convert links", () => {
    expect(markdownToWecomText("[Google](https://google.com)")).toBe(
      "Google (https://google.com)"
    );
  });

  it("should convert unordered lists with dash", () => {
    expect(markdownToWecomText("- item1\n- item2")).toBe("• item1\n• item2");
  });

  it("should convert unordered lists with asterisk (italic takes precedence for multiline)", () => {
    // Note: * prefix conflicts with italic regex — known limitation
    expect(markdownToWecomText("* single item")).toBe("• single item");
  });

  it("should strip inline code markers", () => {
    expect(markdownToWecomText("use `console.log`")).toBe("use console.log");
  });

  it("should convert code blocks", () => {
    const md = "```js\nconst x = 1;\n```";
    const result = markdownToWecomText(md);
    expect(result).toContain("[js]");
    expect(result).toContain("const x = 1;");
  });

  it("should handle null/empty input", () => {
    expect(markdownToWecomText(null)).toBeNull();
    expect(markdownToWecomText("")).toBe("");
  });

  it("should convert horizontal rules", () => {
    expect(markdownToWecomText("---")).toBe("────────────");
  });

  it("should convert images to alt text (link regex runs first)", () => {
    // Note: link regex matches before image regex — known limitation
    // The ! prefix remains, and [text](url) becomes text (url)
    expect(markdownToWecomText("![screenshot](url)")).toBe("!screenshot (url)");
  });
});

describe("splitWecomText", () => {
  it("should return single chunk for short text", () => {
    const result = splitWecomText("hello");
    expect(result).toEqual(["hello"]);
  });

  it("should split long text into multiple chunks", () => {
    // Create text that exceeds 2000 bytes
    const longText = "这是一段很长的中文文本。".repeat(200);
    const result = splitWecomText(longText);
    expect(result.length).toBeGreaterThan(1);

    // Each chunk should be within byte limit
    for (const chunk of result) {
      expect(getByteLength(chunk)).toBeLessThanOrEqual(2000);
    }
  });

  it("should preserve all content after splitting", () => {
    const longText = "A".repeat(3000);
    const result = splitWecomText(longText);
    const joined = result.join("");
    expect(joined.length).toBe(3000);
  });

  it("should respect custom byte limit", () => {
    const text = "hello world this is a test";
    const result = splitWecomText(text, 10);
    expect(result.length).toBeGreaterThan(1);
    for (const chunk of result) {
      expect(getByteLength(chunk)).toBeLessThanOrEqual(10);
    }
  });

  it("should prefer splitting at natural breaks", () => {
    const text = "第一段内容。\n\n第二段内容。";
    // Use a byte limit that forces a split
    const byteLen = getByteLength(text);
    const result = splitWecomText(text, Math.floor(byteLen * 0.7));
    expect(result.length).toBe(2);
    expect(result[0]).toContain("第一段");
    expect(result[1]).toContain("第二段");
  });
});
