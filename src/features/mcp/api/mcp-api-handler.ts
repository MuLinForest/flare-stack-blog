import { WorkerEntrypoint } from "cloudflare:workers";
import { createMcpHandler } from "agents/mcp";
import {
  createOAuthPrincipalFromProps,
  extractBearerToken,
} from "@/features/oauth-provider/service/oauth-provider.service";
import { OAUTH_DEFAULT_CLIENT_SCOPES } from "@/features/oauth-provider/oauth-provider.shared";
import { getDb } from "@/lib/db";
import { createMcpServer } from "../service/mcp.server";
import {
  applyMcpOriginPolicy,
  createInvalidOriginResponse,
  isAllowedMcpOrigin,
} from "../utils/mcp-origin";

type OAuthProps = Record<string, unknown>;

function getOAuthProps(ctx: ExecutionContext): OAuthProps {
  const maybeContext = ctx as ExecutionContext & { props?: OAuthProps };
  return maybeContext.props ?? {};
}

export class McpApiHandler extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (!isAllowedMcpOrigin(request)) {
      return createInvalidOriginResponse();
    }

    const executionCtx = this.ctx as ExecutionContext;
    let authProps = getOAuthProps(executionCtx);

    // API Key bypass: if Bearer token matches MCP_API_KEY env var, skip OAuth
    const bearerToken = extractBearerToken(request.headers.get("authorization"));
    if (bearerToken && this.env.MCP_API_KEY && bearerToken === this.env.MCP_API_KEY) {
      authProps = {
        clientId: "mcp-api-key",
        scopes: OAUTH_DEFAULT_CLIENT_SCOPES,
        subject: "api-key-user",
      };
    }

    const db = getDb(this.env);
    const server = await createMcpServer({
      db,
      env: this.env,
      executionCtx,
      principal: createOAuthPrincipalFromProps(authProps),
    });

    const response = await createMcpHandler(
      server as unknown as Parameters<typeof createMcpHandler>[0],
      {
        authContext: {
          props: authProps,
        },
        route: "/mcp",
      },
    )(request, this.env, executionCtx);

    return applyMcpOriginPolicy(request, response);
  }
}
