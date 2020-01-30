import axios from "axios";
import * as qs from "query-string";
import * as shajs from "sha.js";

export interface OAuth2Token {
  accessToken: string;
  refreshToken?: string;
}

export class CryptoBadgeOAuth2Client {
  private readonly AUTHORIZATION_ENDPOINT_URL = "https://accounts.cryptobadge.app/oauth2/authorize";
  private readonly TOKEN_ENDPOINT_URL = "https://accounts.cryptobadge.app/oauth2/token";
  private readonly DEFAULT_SCOPES = ["email"];

  public constructor(
    public readonly clientId: string,
    public readonly redirectUrl: string,
  ) {}

  public getAuthorizeEndpoint() {
    const verifier = this.randomBytes(32);
    const pkce = {
      verifier,
      challenge: shajs("sha256").update(verifier).digest("base64")
        .replace(/=+$/, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_"),
      algorithm: "S256",
    };

    const params = {
      client_id: this.clientId,
      response_type: "code",
      redirect_uri: this.redirectUrl,
      scope: this.DEFAULT_SCOPES.join(" "),
      state: this.randomBytes(16),
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    };

    return {
      url: `${this.AUTHORIZATION_ENDPOINT_URL}?${qs.stringify(params)}`,
      state: params.state,
      verifier,
    };
  }

  public async getAccessToken(code: string, verifier: string): Promise<OAuth2Token> {
    const params = {
      client_id: this.clientId,
      redirect_uri: this.redirectUrl,
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
    };

    try {
      const res = await axios({
        method: "POST",
        url: this.TOKEN_ENDPOINT_URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: qs.stringify(params),
        // Currently axios have an issue with forcing `text` response type.
        // @see https://github.com/axios/axios/issues/907
        responseType: "text",
      });

      const data = this.transformResponse(res.data);
      const tokens = this.extractToken(data);

      if (!tokens.accessToken) {
        throw new Error("Failed to find access token from provider response");
      }

      return tokens as OAuth2Token;
    } catch (e) {
      console.error("OAuth2 token exchange failure was detected: ", e.stack);
      if (e.response) {
        console.error("Response from OAuth server (status: %d): ", e.response.status, e.response.headers, e.response.data);
        const data = this.transformResponse(e.response.data);

        const error = (data.error_description || data.error) as string | undefined;

        if (error) {
          throw new Error(error);
        }
      }

      throw new Error("Authentication Failed");
    }
  }

  private transformResponse(data: any): { [key: string]: unknown } {
    const parsers = [
      (input: any) => typeof input === "object" ? input : null,
      (input: any) => {
        try {
          return JSON.parse(input);
        } catch (e) { /* no op */ }

        return null;
      },
      (input: any) => {
        try {
          const parsed = qs.parse(input);
          const size = Object.keys(parsed).length;

          if (size > 0) { return parsed; }
        } catch (e) { /* no op */ }

        return null;
      },
    ];

    for (const parser of parsers) {
      const parsed = parser(data);
      if (parsed) {
        return parsed;
      }
    }

    return {};
  }

  private extractToken(data: { [key: string]: unknown }): Partial<OAuth2Token> {
    const accessToken = data.access_token as string | undefined;
    const refreshToken = data.refresh_token as string | undefined;

    return {
      accessToken,
      refreshToken,
    };
  }

  private randomBytes(size: number): string {
    const buf = crypto?.getRandomValues?.(new Uint8Array(size)) ??
      Array.prototype.map.call(new Array(size), () => Math.floor(Math.random() * 255));

    return Array.prototype.map.call(buf, (b: number) => `00${b.toString(16)}`.slice(-2))
      .join("");
  }
}
