import PostalMime from "postal-mime";
import { createRequestHandler } from "react-router";
import {
  cleanupExpiredEmails,
  createDB,
  getOrCreateMailbox,
  storeEmail,
} from "../app/lib/db";

const requestHandler = createRequestHandler(
  () => import("virtual:react-router/server-build"),
  import.meta.env.MODE,
);

interface ParsedEmail {
  messageId?: string;
  from?: {
    name?: string;
    address?: string;
  };
  to?: Array<{
    name?: string;
    address?: string;
  }>;
  subject?: string;
  text?: string;
  html?: string;
  attachments?: Array<{
    filename?: string;
    mimeType?: string;
    size?: number;
    contentId?: string;
    related?: boolean;
    content?: ArrayBuffer;
  }>;
}

// 直接写死密钥，正式建议用环境变量注入
const HMAC_SECRET = "e3f2a7d5c6b49817a7e3f2a7d5c6b49817a7e3f2a7d5c6b49817a7e3f2a7d5c6b4";

export default {
  async fetch(request, env, ctx) {
    return requestHandler(request, {
      cloudflare: { env, ctx },
    });
  },
  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      // 这里用硬编码密钥
      const hmacSecret = HMAC_SECRET;
      if (!hmacSecret) {
        throw new Error("HMAC_SECRET is not set");
      }

      const signatureBase64 = message.headers.get("X-Signature");
      if (!signatureBase64) {
        throw new Error("Missing HMAC signature in email headers");
      }

      const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

      const keyData = new TextEncoder().encode(hmacSecret);
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );

      const rawArrayBuffer = await new Response(message.raw).arrayBuffer();

      const isValid = await crypto.subtle.verify(
        "HMAC",
        cryptoKey,
        signatureBytes,
        rawArrayBuffer,
      );

      if (!isValid) {
        throw new Error("Invalid HMAC signature");
      }

      console.log(`📧 Received email: ${message.from} -> ${message.to}, size: ${message.rawSize}`);

      const db = createDB();

      ctx.waitUntil(cleanupExpiredEmails(db));

      const rawEmailArray = rawArrayBuffer;
      const rawEmail = new TextDecoder().decode(rawEmailArray);

      const parsedEmail = (await PostalMime.parse(rawEmailArray)) as ParsedEmail;

      console.log(`📝 Parsed email from: ${parsedEmail.from?.address}, subject: ${parsedEmail.subject}`);

      const mailbox = await getOrCreateMailbox(db, message.to);

      console.log(`📦 Found/Created mailbox: ${mailbox.id} for ${mailbox.email}`);

      const emailId = await storeEmail(
        db,
        env.ATTACHMENTS,
        mailbox.id,
        parsedEmail,
        rawEmail,
        message.rawSize,
        message.to,
      );

      console.log(`✅ Email stored successfully with ID: ${emailId}`);
    } catch (error) {
      console.error("❌ Error processing email:", error);
      // message.setReject("Email processing failed");
    }
  },
} satisfies ExportedHandler<Env>;
