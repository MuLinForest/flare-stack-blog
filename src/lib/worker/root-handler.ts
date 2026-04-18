import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { McpApiHandler } from "@/features/mcp/api/mcp-api-handler";
import { createWorkersOAuthProviderOptions } from "@/features/oauth-provider/oauth-provider.config";
import { extractBearerToken } from "@/features/oauth-provider/service/oauth-provider.service";
import { OAUTH_DEFAULT_CLIENT_SCOPES } from "@/features/oauth-provider/oauth-provider.shared";
import { getDb } from "@/lib/db";
import { createMcpServer } from "@/features/mcp/service/mcp.server";
import { createOAuthPrincipalFromProps } from "@/features/oauth-provider/service/oauth-provider.service";
import { createMcpHandler } from "agents/mcp";
import {
  applyMcpOriginPolicy,
  createInvalidOriginResponse,
  isAllowedMcpOrigin,
} from "@/features/mcp/utils/mcp-origin";
import { appWorkerHandler } from "./app-handler";

let oauthProvider: OAuthProvider<Env> | null = null;

function getOAuthProvider() {
  if (oauthProvider) {
    return oauthProvider;
  }

  oauthProvider = new OAuthProvider(
    createWorkersOAuthProviderOptions({
      apiHandlers: {
        "/mcp": McpApiHandler,
      },
      defaultHandler: appWorkerHandler,
    }),
  );

  return oauthProvider;
}

async function handleMcpWithApiKey(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  if (!isAllowedMcpOrigin(request)) {
    return createInvalidOriginResponse();
  }

  const authProps = {
    clientId: "mcp-api-key",
    scopes: OAUTH_DEFAULT_CLIENT_SCOPES,
    subject: "api-key-user",
  };

  const db = getDb(env);
  const server = await createMcpServer({
    db,
    env,
    executionCtx: ctx,
    principal: createOAuthPrincipalFromProps(authProps),
  });

  const response = await createMcpHandler(
    server as unknown as Parameters<typeof createMcpHandler>[0],
    {
      authContext: { props: authProps },
      route: "/mcp",
    },
  )(request, env, ctx);

  return applyMcpOriginPolicy(request, response);
}

export function handleRootRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
) {
  // API Key bypass: intercept /mcp before OAuthProvider validates the token
  const url = new URL(request.url);
  if (url.pathname === "/mcp" && env.MCP_API_KEY) {
    const bearerToken = extractBearerToken(request.headers.get("authorization"));
    if (bearerToken === env.MCP_API_KEY) {
      return handleMcpWithApiKey(request, env, ctx);
    }
  }

  return getOAuthProvider().fetch(request, env, ctx);
}
