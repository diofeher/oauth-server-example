import * as vscode from "vscode";
import { OAuthAuthenticationProvider } from "./authProvider";

let authProvider: OAuthAuthenticationProvider;

export function activate(context: vscode.ExtensionContext) {
  authProvider = new OAuthAuthenticationProvider(context);

  context.subscriptions.push(
    vscode.authentication.registerAuthenticationProvider(
      OAuthAuthenticationProvider.id,
      "OAuth Demo",
      authProvider,
      { supportsMultipleAccounts: false }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("oauthDemo.signIn", async () => {
      try {
        const session = await vscode.authentication.getSession(
          OAuthAuthenticationProvider.id,
          [],
          { createIfNone: true }
        );
        vscode.window.showInformationMessage(
          `Signed in as ${session.account.label}`
        );
      } catch (e: any) {
        vscode.window.showErrorMessage(`Sign in failed: ${e.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("oauthDemo.signOut", async () => {
      await authProvider.removeSession();
      vscode.window.showInformationMessage("Signed out");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("oauthDemo.getUserInfo", async () => {
      const session = await vscode.authentication.getSession(
        OAuthAuthenticationProvider.id,
        [],
        { createIfNone: false }
      );
      if (!session) {
        vscode.window.showWarningMessage("Not signed in. Run 'Sign In' first.");
        return;
      }
      try {
        const resp = await fetch("http://localhost:8080/userinfo", {
          headers: { Authorization: `Bearer ${session.accessToken}` },
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        const data = await resp.json();
        vscode.window.showInformationMessage(
          `User info: ${JSON.stringify(data)}`
        );
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to get user info: ${e.message}`);
      }
    })
  );
}

export function deactivate() {}
