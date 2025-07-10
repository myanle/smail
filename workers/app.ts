import PostalMime from "postal-mime";
import { createRequestHandler } from "react-router";
import {
  cleanupExpiredEmails,
  createDB,
  getOrCreateMailbox,
  storeEmail,
} from "../app/lib/db";

declare module "react-router" {
  export interface AppLoadContext {
    cloudflare: {
      env: Env;
      ctx: ExecutionContext;
    };
  }
}

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

// 写死的16进制HMAC密钥（示例）
const HMAC_SECRET = "e3f2a7d5c6b49817a7e3f2a7d5c6b49817a7e3f2a7d5c6b49817a7e3f2a7d5c6b4";

// 将16进制字符串转换成Uint8Array
function hexToUint8Array(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

export default {
  async fetch(request, env, ctx) {
    return requestHandler(request, {
      cloudflare: { env, ctx },
    });
  },
  async email(
    message: ForwardableEmailMessage,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    try {
      const hmacSecret = HMAC_SECRET.trim();
      if (!hmacSecret) {
        throw new Error("HMAC_SECRET is not set");
      }

      // 从邮件头获取签名，示例用 X-Signature
      const signatureBase64 = message.headers.get("X-Signature");
      if (!signatureBase64) {
        throw new Error("Missing HMAC signature in email headers");
      }

      // 解码签名Base64到Uint8Array
      const signatureBytes = Uint8Array.from(
        atob(signatureBase64),
        (c) => c.charCodeAt(0),
      );

      // 把16进制密钥转换成字节数组
      const keyData = hexToUint8Array(hmacSecret);

      // 导入密钥
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyData.buffer,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );

      // message.raw 是邮件原始内容（ArrayBuffer 或字符串？），先转换成ArrayBuffer
      const rawArrayBuffer = await new Response(message.raw).arrayBuffer();

      // 验证签名
      const isValid = await crypto.subtle.verify(
        "HMAC",
        cryptoKey,
        signatureBytes,
        rawArrayBuffer,
      );

      if (!isValid) {
        throw new Error("Invalid HMAC signature");
      }

      // --- 以下为你原本代码 ---
      console.log(
        `📧 Received email: ${message.from} -> ${message.to}, size: ${message.rawSize}`,
      );

      const db = createDB();

      ctx.waitUntil(cleanupExpiredEmails(db));

      const rawEmailArray = rawArrayBuffer;
      const rawEmail = new TextDecoder().decode(rawEmailArray);

      const parsedEmail = (await PostalMime.parse(
        rawEmailArray,
      )) as ParsedEmail;

      console.log(
        `📝 Parsed email from: ${parsedEmail.from?.address}, subject: ${parsedEmail.subject}`,
      );

      const mailbox = await getOrCreateMailbox(db, message.to);

      console.log(
        `📦 Found/Created mailbox: ${mailbox.id} for ${mailbox.email}`,
      );

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
      // message.setReject("Email processing failed"); // 如需要拒绝邮件，可取消注释
    }
  },
} satisfies ExportedHandler<Env>;
