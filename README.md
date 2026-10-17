# Security Audit — Paseo

Security audit of the [getpaseo/paseo](https://github.com/getpaseo/paseo) repository.

| | |
|---|---|
| **Audited commit** | `06cdc5a0b83a2f2f6875613441a86aaa96e59c15` (2026-10-17) |
| **Audit date** | 2026-10-17 |
| **Method** | Static code review (read-only, no code executed) |
| **Scope** | Daemon (`packages/server`), relay and E2EE (`packages/relay`), clients (`packages/app`, `packages/client`), Electron desktop (`packages/desktop`), CI/CD, Docker, supply chain |

## Overall verdict

The project is fairly solid. I found no command injection, no zip-slip and no obvious XSS. A malicious website cannot take over the local daemon, because the Origin and Host headers are checked. Real weaknesses remain, mostly in the relay protocol and in what AI agents are allowed to do.

## Summary

| # | Severity | Finding |
|---|---|---|
| 1 | 🔴 High | A malicious relay can replay a full session |
| 2 | 🔴 High | The password does not protect relay connections |
| 3 | 🟠 Medium | An agent can escalate itself to `bypassPermissions` |
| 4 | 🟠 Medium | The fork-PR gate is bypassed by `.claude/settings.json` |
| 5 | 🟠 Medium | Pages served by the service proxy can control the daemon |
| 6 | 🟠 Medium | Docker is insecure by default |
| 7 | 🟠 Medium | Electron main window is weakly locked down |
| 8 | 🟠 Medium | No CSP or security headers on app.paseo.sh |
| 9 | 🟠 Medium | CI/CD: unprotected signing secrets, actions pinned by tag |
| 10+ | 🟡 Low / Info | See the dedicated section |

---

## 🔴 High

### 1. A malicious relay can replay a full session

**Files:** `packages/relay/src/encrypted-channel.ts:274`, `packages/relay/src/crypto.ts:134`

- The session key is derived only from the daemon's static key and the client's ephemeral key: `DH(daemon secret key, client public key)`. The daemon contributes nothing fresh (no ephemeral key, no nonce).
- A compromised relay can therefore record a session (the `e2ee_hello` and every encrypted client frame), then replay it later in a new connection. The daemon derives the same key, decrypts everything and re-executes the commands: agent prompts, terminal input, and even the `hello` containing the password.
- The relay cannot read the replies, but the side effects happen.
- This directly contradicts SECURITY.md, which states that cross-session replay is impossible.

**Fix:** have the daemon send a fresh ephemeral key in `e2ee_ready`, derive the session key from both the static and ephemeral DH, and add per-direction message counters.

### 2. The password does not protect relay connections

**File:** `packages/server/src/server/session-admission-auth.ts:22`

- For compatibility with older mobile apps (`COMPAT(relayPasswordOptional)`), a relay client that sends no password is admitted as owner (`OWNER_PERMISSIONS`), even when a password is configured.
- Consequence: a leaked pairing link or QR code (screenshot, browser history, `relay://…?key=…` URI) gives full control of the daemon, and therefore code execution.
- This is documented as temporary, but it is the most concrete risk today.
- Note: Hub enrollment sends the daemon's `serverId` and public key to that Hub (`server/src/server/hub/relationship-remote.ts:103`). That Hub therefore also gets owner control, which is not documented.

**Fix:** require the password over the relay as soon as the updated mobile apps are released.

---

## 🟠 Medium

### 3. An agent can escalate itself to `bypassPermissions`

**Files:** `packages/server/src/server/agent/tools/paseo-tools.ts:3155` (`set_agent_mode`), `:3212` (`respond_to_permission`), `:557` (`create_agent`)

- `set_agent_mode` and `respond_to_permission` accept any `agentId`, without comparing it to the calling agent and without blocking a switch to a more permissive mode. `create_agent` also accepts any `mode`.
- These tools are injected into agents by default.
- A prompt injection, for example in a PR the agent is reviewing, can make it disable its own safeguards, spawn a child agent in `bypassPermissions`, or approve another agent's requests.
- With Claude in its default mode, the user still has to approve one MCP tool prompt. With auto-accept providers, that last safeguard disappears.

**Fix:** prevent agents from raising the permissions of any agent (including themselves) or approving permission requests; reserve these actions for the human operator.

### 4. The fork-PR gate is bypassed by `.claude/settings.json`

**File:** `packages/server/src/server/agent/providers/claude/agent.ts:153` (`settingSources: ["user", "project", "local"]`)

- Paseo correctly blocks a fork's `paseo.json` (setup scripts, automatic terminals, teardown).
- But launching a Claude agent in that worktree loads the fork's `project` and `local` settings: `SessionStart` hooks, `permissions.allow` rules, MCP servers. The fork's code therefore runs as soon as the agent starts.
- SECURITY.md excludes agent launches from this gate, which makes it useless for the main use case (opening a fork PR and launching an agent to review it).

**Fix:** for workspaces flagged `untrustedSource`, drop `"project"` and `"local"` from `settingSources` until the user has explicitly approved the workspace.

### 5. Pages served by the service proxy can control the daemon

**Files:** `packages/server/src/server/websocket-server.ts:2927` (`isWebSocketSameOrigin`, `isLoopbackAlias`), `packages/server/src/server/service-proxy.ts:147`

- Any `*.localhost` origin on port 6767 is treated as "same-origin". Yet workspace dev servers are published precisely at `<script>.<branch>.<project>.localhost:6767` addresses.
- A third-party script loaded in the web app you are developing (analytics, ads, XSS) can open `ws://localhost:6767/ws`, send `hello` and take control of the daemon if no password is set.

**Fix:** require an exact origin match for loopback and never treat service hostnames as same-origin.

### 6. Docker is insecure by default

**Files:** `docker/base/Dockerfile:34`, `docker/base/rootfs/usr/local/bin/paseo-docker-entrypoint:60`, `docker/docker-compose.example.yml:11`

- The container listens on `0.0.0.0:6767` and starts without a password, with only a warning.
- The example compose file publishes the port on all interfaces with the password `change-me`.
- Anyone on the network can then control the daemon (agents, commands, agent credentials).

**Fix:** refuse to start without a password when the listen address is not loopback; publish the port on `127.0.0.1:6767:6767` in the compose example.

### 7. Electron main window is weakly locked down

**Files:** `packages/desktop/src/window/window-manager.ts:402`, `packages/desktop/src/preload.ts:35`, `packages/desktop/src/daemon/daemon-manager.ts:480`

- The main window has no navigation restriction (except `file://`) and no `setWindowOpenHandler`.
- The preload exposes a generic `invoke`, and no IPC handler checks the sender (`event.senderFrame.url`). It notably allows reading any file (`copy_attachment_file` + `read_file_base64`), retrieving the daemon's local credential (`desktop_local_credential`) and calling `shell.openPath`.
- This is not exploitable on its own, but a future XSS would turn into code execution.
- On the plus side, the built-in browser is properly isolated.

**Fix:** restrict navigation to `paseo://app`, deny `window.open`, and check the sender URL in every IPC handler.

### 8. No CSP or security headers on app.paseo.sh

**File:** `packages/app/public/index.html` (no CSP, no `_headers` file)

- This page receives the daemon key in the URL fragment (`#offer=…`).
- No third-party script is loaded there today, but a CSP would limit the damage of a potential XSS (key theft).

**Fix:** add a `_headers` file with `script-src 'self'`, a restricted `connect-src`, `frame-ancestors 'none'` and `Referrer-Policy: no-referrer`.

### 9. CI/CD

**Files:** `.github/workflows/desktop-release.yml:159`, `android-apk-release.yml:96`, `nix-update-hash.yml:28`, `docker.yml:144`

- The Apple signing secrets are not protected by any `environment:` with required reviewers, and the `checkout_ref` input is free-form. Anyone with write access (or a stolen maintainer token) can therefore publish a signed, notarized update.
- Several privileged third-party actions are pinned by tag rather than by SHA (`expo/expo-github-action@v8`, `cachix/install-nix-action@v31`, `docker/login-action@v4`, `docker/build-push-action@v7`).

**Fix:** move signing jobs into a protected environment, restrict `checkout_ref`, pin actions by SHA.

---

## 🟡 Low / Info

- **Unverified `callerAgentId`** (`server/src/server/bootstrap.ts:1556`): it is a plain URL parameter on `/mcp/agents`. By omitting it, an agent bypasses its provider's tool policy. The tool policy is therefore not a security boundary.
- **Fork teardown without the gate** (`server/src/server/workspace-archive-service.ts:237`): archiving a workspace by path can run a fork's teardown without going through the gate.
- **Unauthenticated relay** (`relay/src/cloudflare-adapter.ts:347`): knowing the `serverId` is enough to disconnect the daemon or hijack a socket (DoS). The daemon also opens outbound sockets without limit (`server/src/server/relay-transport.ts:309`).
- **No direction separation** in relay encryption: messages can be reflected (no known exploit today). The `binaryCiphertext` negotiation can be downgraded by the relay.
- **No rate limiting** on password attempts: only matters when the daemon is exposed to the network.
- **No Electron fuses** (`RunAsNode` stays enabled) and **unsigned Windows installers**.
- **Password stored in plaintext on mobile** in AsyncStorage (`app/src/runtime/host-runtime.ts:2235`) instead of SecureStore or the Keychain.
- **Incomplete `.cmd` escaping on Windows** (`desktop/src/features/editor-targets/runtime.ts`): `%VAR%` is still expanded.
- **Workflows without default `permissions:`** (`ci.yml`, `deploy-*.yml`) and a workflow input interpolated into a `run:` block (`desktop-rollout.yml:146`).
- **`cli-client-id` file committed by mistake** at the repo root; it is not a secret.

---

## ✅ Verified positive controls

- **Local daemon access:** strict Host and Origin checks (no DNS rebinding or cross-site WebSocket hijacking), constant-time token comparisons.
- **Sensitive files:** keypair, `config.json` and `local-credential` written with `0600` permissions; `$PASEO_HOME` is `0700`.
- **Git:** run without a shell, branch names validated (`git check-ref-format`), `core.fsmonitor` disabled.
- **Fork PRs:** detected through the forge API, not through repository names an attacker could spoof.
- **Plugins:** HTTPS registry, integrity checked by `sha512` or pinned commit, `--ignore-scripts`.
- **Relay encryption:** the daemon key only comes from the QR/link, never from the relay; correct handshake state machine; random nonces; low-order keys rejected.
- **Markdown:** rendered with `html: false`, Mermaid in `strict` mode, HTML previews in a sandboxed iframe.
- **Electron:** `contextIsolation` enabled, `nodeIntegration` disabled, `shell.openExternal` limited to http/https, built-in browser isolated.
- **CI:** no `pull_request_target` and no injection via `github.event`.

---

## Recommendations for Paseo users

- **Set a password**, even though it does not yet cover the relay (finding 2).
- **Treat the pairing link or QR code as a secret** and regenerate the keypair if it leaks. To do so, delete `$PASEO_HOME/daemon-keypair.json` and restart the daemon.
- **Do not launch an agent in an unreviewed fork PR**: its `.claude/` settings run when the agent starts.
- **Do not expose the daemon to the network** (Docker, tunnel, `0.0.0.0`) without a strong password.

## Limitations

- Static review only: no finding was reproduced at runtime.
- Dependencies were not installed; third-party library code (e.g. `react-native-enriched-markdown`) was not reviewed.
- Severities are estimated against the threat model described in the project's SECURITY.md.
