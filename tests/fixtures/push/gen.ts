// Generates `t3-vectors.json`: what T3 Code's relay (infra/relay/src/agentActivity, MIT, Copyright (c)
// T3 Tools Inc.) builds for fixed inputs, by running T3's own modules under Bun. The Rust push
// tests compare against it byte for byte (after the Vekrel renames: environmentId -> machineId,
// "T3 Code" -> "Vekrel"). Test tooling only; nothing here runs in the relay.
//
//   T3=<t3code checkout> ENGINE=<Vekrel-Engine checkout> bun tests/fixtures/push/gen.ts \
//     > tests/fixtures/push/t3-vectors.json
//
// effect 4.0.5 and @noble/* 1.9.1/1.8.0 (T3's catalog versions) come from the Engine's pnpm store.
// T3's sources are copied unchanged into a temp dir next to a node_modules of symlinks; modules that
// only matter for the database (drizzle, db.ts, ...) are replaced by empty stubs.
import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SRC = `${process.env.T3}/infra/relay/src`;
const PNPM = `${process.env.ENGINE}/node_modules/.pnpm`;
const work = mkdtempSync(join(tmpdir(), "vekrel-push-gen-"));
process.on("exit", () => rmSync(work, { recursive: true, force: true }));
const T3 = join(work, "src");
mkdirSync(join(T3, "agentActivity"), { recursive: true });
cpSync(join(SRC, "agentActivity"), join(T3, "agentActivity"), { recursive: true });
for (const f of ["Config.ts", "WebCrypto.ts"]) cpSync(join(SRC, f), join(T3, f));
for (const f of ["db.ts", "persistence/schema.ts", "environments/EnvironmentLinks.ts",
  "agentActivity/AgentActivityRows.ts", "agentActivity/LiveActivities.ts", "agentActivity/FcmDeliveryQueueSender.ts"]) {
  mkdirSync(join(T3, f, ".."), { recursive: true });
  // Named imports must exist; only the database code (never called here) uses them.
  writeFileSync(join(T3, f), "export const relayMobileDevices={},relayLiveActivities={},relayAgentActivityRows={},relayEnvironmentLinks={};\n");
}
const nm = join(work, "node_modules");
mkdirSync(join(nm, "@noble"), { recursive: true });
symlinkSync(`${PNPM}/effect@4.0.5/node_modules/effect`, join(nm, "effect"));
symlinkSync(`${PNPM}/@noble+curves@1.9.1/node_modules/@noble/curves`, join(nm, "@noble/curves"));
symlinkSync(`${PNPM}/@noble+hashes@1.8.0/node_modules/@noble/hashes`, join(nm, "@noble/hashes"));
const pkg = (name: string, files: Record<string, string>) => {
  const dir = join(nm, name);
  mkdirSync(dir, { recursive: true });
  const exports = Object.fromEntries(Object.keys(files).map((k) => [k === "index.js" ? "." : `./${k.replace(/\.js$/, "")}`, `./${k}`]));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, type: "module", exports }));
  for (const [k, v] of Object.entries(files)) writeFileSync(join(dir, k), v);
};
pkg("drizzle-orm", { "index.js": "export const and=()=>0,eq=()=>0,sql=()=>0,isNotNull=()=>0,isNull=()=>0,desc=()=>0,lt=()=>0,or=()=>0;" });
pkg("@t3tools/contracts", {
  "relay.js": `import * as S from "effect/Schema";
export const RelayAgentActivityState=S.Unknown,RelayAgentActivityAggregateState=S.Unknown,
RelayAgentAwarenessPreferences=S.Unknown,RelayDeliveryKind=S.Unknown,RelayAgentAwarenessPhase=S.Unknown;`,
});
writeFileSync(join(work, "deps.ts"), `export * as Effect from "effect/Effect";
export * as Layer from "effect/Layer";
export * as Redacted from "effect/Redacted";
export * as HttpClient from "effect/http/HttpClient";
export * as HttpClientResponse from "effect/http/HttpClientResponse";
export { p256 } from "@noble/curves/nist";
`);
const { Effect, Layer, Redacted, HttpClient, HttpClientResponse, p256 } = await import(join(work, "deps.ts"));

const aggregate = await import(`${T3}/agentActivity/agentActivityAggregate.ts`);
const payloads = await import(`${T3}/agentActivity/agentActivityPayloads.ts`);
const alerts = await import(`${T3}/agentActivity/agentActivityAlerts.ts`);
const fcmPayloads = await import(`${T3}/agentActivity/fcmPayloads.ts`);
const fcmDeliveries = await import(`${T3}/agentActivity/FcmDeliveries.ts`);
const ApnsClient = await import(`${T3}/agentActivity/ApnsClient.ts`);
const ApnsProviderTokens = await import(`${T3}/agentActivity/ApnsProviderTokens.ts`);
const FcmClient = await import(`${T3}/agentActivity/FcmClient.ts`);
const FcmAssertionSigner = await import(`${T3}/agentActivity/FcmAssertionSigner.ts`);
const RelayConfiguration = await import(`${T3}/Config.ts`);
const WebCrypto = await import(`${T3}/WebCrypto.ts`);

const NOW_MS = Date.parse("2026-10-24T12:00:00.000Z");
const iso = (offsetMs: number) => new Date(NOW_MS + offsetMs).toISOString();
const MIN = 60_000;

const state = (o: Record<string, unknown>) => ({
  environmentId: "machine-1",
  threadId: "thread-1",
  projectTitle: "Project",
  threadTitle: "Thread",
  phase: "running",
  headline: "Working",
  modelTitle: "gpt-5.4",
  updatedAt: iso(-MIN),
  deepLink: "/threads/machine-1/thread-1",
  ...o,
});

const long = "Long title ".repeat(14);
const states = {
  running: state({}),
  approval: state({ threadId: "t-approval", phase: "waiting_for_approval", updatedAt: iso(-2 * MIN) }),
  input: state({ threadId: "t-input", phase: "waiting_for_input", updatedAt: iso(-3 * MIN) }),
  starting: state({ threadId: "t-starting", phase: "starting", updatedAt: iso(-4 * MIN) }),
  stale: state({ threadId: "t-stale", phase: "stale", updatedAt: iso(-5 * MIN) }),
  failedRecent: state({ threadId: "t-failed", phase: "failed", updatedAt: iso(-30_000) }),
  completedRecent: state({ threadId: "t-done", phase: "completed", updatedAt: iso(-6 * MIN) }),
  completedOld: state({ threadId: "t-old", phase: "completed", updatedAt: iso(-20 * MIN) }),
  expiredRunning: state({ threadId: "t-expired", phase: "running", updatedAt: iso(-3 * 60 * MIN) }),
  waitingDayOld: state({ threadId: "t-day", phase: "waiting_for_input", updatedAt: iso(-25 * 60 * MIN) }),
  messy: state({
    environmentId: "machine-2",
    threadId: "t-messy",
    projectTitle: `  ${long}  `,
    threadTitle: "界".repeat(130),
    modelTitle: "Model 😀 with emoji",
    deepLink: "//evil.example/path",
    updatedAt: iso(-7 * MIN),
  }),
  badLink: state({ threadId: "t-badlink", deepLink: "https://evil.example/", updatedAt: iso(-8 * MIN) }),
  nel: state({ threadId: "t-nel", threadTitle: "\u0085Next line\ufeff", projectTitle: "\ufeff P ", updatedAt: iso(-10 * MIN) }),
  tabs: state({ threadId: "t-tabs", threadTitle: "Tab\tand\n newline  title", projectTitle: " P roject ", updatedAt: iso(-9 * MIN) }),
};
const S = states;

const aggregateInputs: Record<string, { activeStates: unknown[]; terminalState: unknown | null }> = {
  empty: { activeStates: [], terminalState: null },
  oneRunning: { activeStates: [S.running], terminalState: null },
  mixed: {
    activeStates: [S.running, S.approval, S.failedRecent, S.completedOld, S.starting, S.expiredRunning, S.waitingDayOld],
    terminalState: null,
  },
  terminalOnly: { activeStates: [S.completedRecent, S.failedRecent, S.completedOld], terminalState: null },
  terminalPassed: { activeStates: [S.completedOld], terminalState: S.completedRecent },
  terminalFailedPassed: { activeStates: [], terminalState: S.failedRecent },
  many: {
    activeStates: [S.running, S.approval, S.input, S.starting, S.stale, S.messy, S.badLink, S.tabs, S.failedRecent],
    terminalState: null,
  },
  sanitized: { activeStates: [S.messy, S.badLink, S.tabs, S.nel], terminalState: null },
};

const agg = (k: string) => aggregate.makeAggregateState({ ...aggregateInputs[k]!, nowMs: NOW_MS });
const aggregates = Object.fromEntries(Object.keys(aggregateInputs).map((k) => [k, agg(k)]));

const prefs = (o: Record<string, boolean> = {}) => ({
  liveActivitiesEnabled: true,
  notificationsEnabled: true,
  notifyOnApproval: true,
  notifyOnInput: true,
  notifyOnCompletion: true,
  notifyOnFailure: true,
  ...o,
});

const withPhase = (a: any, threadId: string, phase: string, updatedAt = a.updatedAt) => ({
  ...a,
  activities: a.activities.map((r: any) =>
    r.threadId === threadId ? { ...r, phase, status: aggregate.statusForPhase(phase), updatedAt } : r,
  ),
});
const two = aggregate.makeAggregateState({
  activeStates: [S.running, state({ threadId: "thread-2", threadTitle: "Second", updatedAt: iso(-2 * MIN) })],
  terminalState: null,
  nowMs: NOW_MS,
});
const transitionInputs: Record<string, any> = {
  attention: { previousAggregate: aggregates.oneRunning, nextAggregate: withPhase(aggregates.oneRunning, "thread-1", "waiting_for_approval"), preferences: prefs() },
  attentionMuted: { previousAggregate: aggregates.oneRunning, nextAggregate: withPhase(aggregates.oneRunning, "thread-1", "waiting_for_input"), preferences: prefs({ notifyOnInput: false }) },
  replay: { previousAggregate: null, nextAggregate: aggregates.mixed, preferences: prefs() },
  twoFinished: { previousAggregate: two, nextAggregate: withPhase(withPhase(two, "thread-1", "completed", iso(-10_000)), "thread-2", "failed", iso(-5_000)), preferences: prefs() },
  finishedStale: { previousAggregate: two, nextAggregate: withPhase(two, "thread-1", "completed", iso(-5 * MIN)), preferences: prefs() },
  finishedMuted: { previousAggregate: two, nextAggregate: withPhase(two, "thread-1", "completed", iso(-10_000)), preferences: prefs({ notifyOnCompletion: false }) },
  nullPrefs: { previousAggregate: aggregates.oneRunning, nextAggregate: withPhase(aggregates.oneRunning, "thread-1", "waiting_for_approval"), preferences: null },
};
const transitions = Object.fromEntries(
  Object.entries(transitionInputs).map(([k, input]) => [
    k,
    {
      input,
      attention: alerts.alertForAttentionTransition(input),
      newlyTerminal: alerts.alertForNewlyTerminal({ ...input, nowMs: NOW_MS, includeUnobserved: true }),
      newlyTerminalObservedOnly: alerts.alertForNewlyTerminal({ ...input, nowMs: NOW_MS }),
      rowPhasesChanged: input.previousAggregate ? alerts.rowPhasesChanged(input.previousAggregate, input.nextAggregate) : null,
      androidAggregate: input.previousAggregate && input.preferences
        ? fcmDeliveries.androidAlertForAggregate({ ...input, nowMs: NOW_MS })
        : null,
    },
  ]),
);
const terminalAlerts = Object.fromEntries(
  ["terminalPassed", "terminalFailedPassed", "oneRunning", "empty"].map((k) => [
    k,
    {
      allowed: alerts.alertForTerminalAggregate({ aggregate: aggregates[k], preferences: prefs() }),
      muted: alerts.alertForTerminalAggregate({ aggregate: aggregates[k], preferences: prefs({ notifyOnCompletion: false, notifyOnFailure: false }) }),
    },
  ]),
);

const notifications = Object.fromEntries(
  Object.entries(aggregates)
    .filter(([, a]) => a)
    .map(([k, a]) => [k, payloads.notificationForActivity(a.activities[0])]),
);

const androidStates = Object.fromEntries(
  ["running", "approval", "failedRecent", "completedOld", "messy"].map((k) => [
    k,
    {
      allowed: fcmDeliveries.androidAlertForState((S as any)[k], prefs(), NOW_MS),
      muted: fcmDeliveries.androidAlertForState((S as any)[k], prefs({ notificationsEnabled: false }), NOW_MS),
    },
  ]),
);

// FcmDeliveries.process builds this object, then hashes alert_id and fits it (FcmDeliveries.ts:300-316).
const hex = (s: string) => createHash("sha256").update(s).digest("hex");
const fcmData = (agg: any, alert: any) => {
  const data: Record<string, string> = {
    t3_kind: "agent_activity",
    device_id: "device-1",
    user_id: "user-1",
    updated_at: String(NOW_MS),
    ...fcmPayloads.androidActivityData(agg),
    ...alert,
  };
  if (alert) data.alert_id = hex(alert.alert_id);
  return { raw: data, fitted: fcmPayloads.fitFcmData(data) };
};
const hugeRow = (i: number) => state({ threadId: `t-huge-${i}`, threadTitle: "界".repeat(120), projectTitle: "📦".repeat(60), updatedAt: iso(-(i + 1) * 1000) });
const huge = aggregate.makeAggregateState({ activeStates: [0, 1, 2, 3, 4].map(hugeRow), terminalState: null, nowMs: NOW_MS });
const fcm = {
  empty: fcmData(null, null),
  oneRunning: fcmData(aggregates.oneRunning, null),
  mixed: fcmData(aggregates.mixed, transitions.attention.androidAggregate),
  terminalOnly: fcmData(aggregates.terminalOnly, null),
  sanitized: fcmData(aggregates.sanitized, null),
  many: fcmData(aggregates.many, transitions.twoFinished.androidAggregate),
  huge: fcmData(huge, fcmDeliveries.androidAlertForAggregate({
    previousAggregate: huge,
    nextAggregate: { ...huge, activities: huge.activities.map((r: any) => ({ ...r, phase: "waiting_for_input", status: "Input" })) },
    preferences: prefs(),
    nowMs: NOW_MS,
  })),
};

// ---- HTTP requests, captured from T3's clients ----

type Captured = { method: string; url: string; headers: Record<string, string>; body: string };
const decodeBody = (body: any): string => {
  if (body?.body instanceof Uint8Array) return new TextDecoder().decode(body.body);
  if (typeof body?.body === "string") return body.body;
  return "";
};
const capture = (sink: Captured[], respond: (url: string) => Response) =>
  HttpClient.make((request: any) => {
    const headers = { ...request.headers };
    // Split test-key JWTs (" . ") so secret scanners do not flag the fixture.
    if (headers.authorization?.startsWith("bearer ey")) headers.authorization = headers.authorization.split(".").join(" . ");
    sink.push({ method: request.method, url: request.url, headers, body: decodeBody(request.body) });
    return Effect.succeed(HttpClientResponse.fromWeb(request, respond(request.url)));
  });

// APNs key: P-256 scalar sha256("vekrel-push-test-apns-key"); the Rust test derives the same key.
const apnsScalar = createHash("sha256").update("vekrel-push-test-apns-key").digest();
const apnsPoint = p256.getPublicKey(apnsScalar, false);
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const apnsPem = createPrivateKey({
  key: { kty: "EC", crv: "P-256", d: b64u(apnsScalar), x: b64u(apnsPoint.slice(1, 33)), y: b64u(apnsPoint.slice(33)) },
  format: "jwk",
}).export({ type: "pkcs8", format: "pem" }) as string;
const credentials = (environment: "sandbox" | "production") => ({
  teamId: "TEAM123456",
  keyId: "KEY1234567",
  privateKey: Redacted.make(apnsPem),
  bundleId: "com.example.vekrel",
  environment,
});
const NOW_S = Math.floor(NOW_MS / 1000);

const apnsSent: Captured[] = [];
const apnsLayer = ApnsClient.layer.pipe(
  Layer.provide(ApnsProviderTokens.layer),
  Layer.provide(Layer.succeed(HttpClient.HttpClient, capture(apnsSent, () => new Response("", { status: 200, headers: { "apns-id": "apns-1" } })))),
);
const apnsRequests = await Effect.runPromise(
  Effect.gen(function* () {
    const apns: any = yield* ApnsClient.ApnsClient;
    const base = { token: "fake-live-activity-token-0001", nowEpochSeconds: NOW_S, nowIso: iso(0) };
    const la = {
      updateMixed: apns.makeLiveActivityRequest({ ...base, event: "update", state: aggregates.mixed }),
      updateAlert: apns.makeLiveActivityRequest({ ...base, event: "update", state: aggregates.many, alert: { title: "Thread", body: "Approval: Project" } }),
      endWithState: apns.makeLiveActivityRequest({ ...base, event: "end", state: aggregates.terminalPassed, alert: { title: "Thread", body: "Done: Project" } }),
      endContentless: apns.makeLiveActivityRequest({ ...base, event: "end", state: null }),
    };
    const push = {
      thread: apns.makePushNotificationRequest({ token: "push-token-0001", notification: notifications.mixed }),
      noThread: apns.makePushNotificationRequest({
        token: "push-token-0002",
        notification: { title: "T", body: "B", environmentId: "machine-1", threadId: "", deepLink: "/" },
      }),
    };
    const out: Record<string, unknown> = {};
    for (const [k, request] of Object.entries(la)) {
      const sent = apnsSent.length;
      const result = yield* apns.sendLiveActivityRequest({ credentials: credentials("sandbox"), request, issuedAtUnixSeconds: NOW_S });
      out[`la_${k}`] = { request, http: apnsSent[sent], result };
    }
    for (const [k, request] of Object.entries(push)) {
      const sent = apnsSent.length;
      const result = yield* apns.sendPushNotificationRequest({ credentials: credentials("production"), request, issuedAtUnixSeconds: NOW_S });
      out[`push_${k}`] = { request, http: apnsSent[sent], result };
    }
    return out;
  }).pipe(Effect.provide(apnsLayer)),
);

const { privateKey: rsaPem } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});
const fcmSent: Captured[] = [];
const fcmLayer = FcmClient.layer.pipe(
  Layer.provide(FcmAssertionSigner.layer),
  Layer.provide(Layer.succeed(WebCrypto.WebCrypto, { subtle: crypto.subtle })),
  Layer.provide(
    RelayConfiguration.layer({
      fcmServiceAccount: Redacted.make(
        JSON.stringify({ project_id: "vekrel-test", client_email: "push@vekrel-test.iam.gserviceaccount.com", private_key: rsaPem }),
      ),
    } as any),
  ),
  Layer.provide(
    Layer.succeed(
      HttpClient.HttpClient,
      capture(fcmSent, (url) =>
        url.includes("oauth2")
          ? Response.json({ access_token: "ya29.test-access-token", expires_in: 3599 })
          : Response.json({ name: "projects/vekrel-test/messages/1" }),
      ),
    ),
  ),
);
await Effect.runPromise(
  Effect.gen(function* () {
    const client: any = yield* FcmClient.FcmClient;
    yield* client.send({ token: "fcm-token-1", packageName: "com.example.vekrel", alert: true, data: fcm.mixed.fitted });
    yield* client.send({ token: "fcm-token-2", packageName: null, alert: false, data: fcm.oneRunning.fitted });
  }).pipe(Effect.provide(fcmLayer)),
);
const [oauth, ...fcmMessages] = fcmSent;
const assertion = new URLSearchParams(oauth!.body).get("assertion")!;
const fcmHttp = {
  oauth: { ...oauth, body: oauth!.body.replace(assertion, "<assertion>") },
  assertionSigningInput: assertion.split(".").slice(0, 2).join("."),
  messages: fcmMessages,
};

const vectors = {
  generatedBy: "tests/fixtures/push/gen.ts against T3 infra/relay/src/agentActivity",
  nowMs: NOW_MS,
  states,
  aggregateInputs,
  aggregates,
  huge,
  notifications,
  transitions,
  terminalAlerts,
  androidStates,
  fcm,
  apns: { keySeedLabel: "vekrel-push-test-apns-key", ...apnsRequests },
  fcmHttp,
};
console.log(JSON.stringify(vectors, null, 1));
