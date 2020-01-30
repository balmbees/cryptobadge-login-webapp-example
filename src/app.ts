import { CryptoBadgeOAuth2Client } from "./cryptobadge_client";
import { AuthorizeResult } from "./types";

class Application {
  // When Authorization happens in Group Hub, Default "Hub Client ID" should be used.
  // Otherwise cases (For instance, Authorization from Specific Group)
  // MUST retrieve & use "group-specific client id" by calling Backend API.
  private cryptoBadgeOAuth2Client = new CryptoBadgeOAuth2Client("50fad2a66952105ce4082edfc0bc80d5", "http://www.lvh.me:8080/app/callback.html");

  async authenticate() {
    const { url, state, verifier } = this.cryptoBadgeOAuth2Client.getAuthorizeEndpoint();

    const authorizeResult = await new Promise<AuthorizeResult | null>((resolve) => {
      window.addEventListener("message", onMessage, false);

      const child = window.open(url, "_blank");
      const tid = setInterval(() => {
        if (child.closed) {
          onClose();
        }
      }, 100);

      function onMessage(e: MessageEvent) {
        clearInterval(tid);
        window.removeEventListener("message", onMessage);
        child.close();

        try {
          const data = JSON.parse(e.data);
          if (data.code && data.state) {
            resolve(data);
          } else {
            // Received Malformed message
            // @todo Validate message origin, or inject special identifier to message payload
            resolve(null);
          }
        } catch (e) {
          // Something went wrong
          console.error("Got unexpected data: ", e.data);
          resolve(null);
        }
      }

      // User closed popup - User canceled authorization.
      function onClose() {
        clearInterval(tid);
        window.removeEventListener("message", onMessage);

        resolve(null);
      }
    });

    if (!authorizeResult) {
      alert("User canceled authorization, or errored");
      return;
    }

    if (state !== authorizeResult.state) {
      alert("State verification failure");
      return;
    }

    const tokens = await this.cryptoBadgeOAuth2Client.getAccessToken(authorizeResult.code, verifier);
    console.log("tokens: ", tokens);

    alert(`tokens: ${JSON.stringify(tokens)}`);
  }
}

const app = new Application();
(window as any).app = app;
