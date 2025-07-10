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
			const hmacSecret = env.HMAC_SECRET;
			if (!hmacSecret) {
				throw new Error("HMAC_SECRET is not set");
			}

			// 从邮件头获取签名，示例用 X-Signature
			const signatureBase64 = message.headers.get("X-Signature");
			if (!signatureBase64) {
				throw new Error("Missing HMAC signature in email headers");
			}

			// 解码签名Base64到Uint8Array
			const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

			// 导入密钥
			const keyData = new TextEncoder().encode(hmacSecret);
			const cryptoKey = await crypto.subtle.importKey(
				"raw",
				keyData,
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
