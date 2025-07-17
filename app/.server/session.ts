import { env } from "cloudflare:workers";
import { createWorkersKVSessionStorage } from "@react-router/cloudflare";
import { createCookie } from "react-router";
<meta name="google-adsense-account" content="ca-pub-4494916955569329">
const sessionCookie = createCookie("__session", {
	secrets: [env.SESSION_SECRET],
	sameSite: true,
});

type SessionData = {
	email: string;
};

const { getSession, commitSession, destroySession } =
	createWorkersKVSessionStorage<SessionData>({
		kv: env.KV,
		cookie: sessionCookie,
	});

export { getSession, commitSession, destroySession };
