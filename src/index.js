import crypto from "node:crypto";
import { XMLParser, XMLBuilder } from "fast-xml-parser";
import { normalizePluginHttpPath } from "clawdbot/plugin-sdk";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink, mkdir, appendFile } from "node:fs/promises";
import { existsSync, appendFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import {
  sha1,
  computeMsgSignature,
  decodeAesKey,
  pkcs7Unpad,
  decryptWecom,
  parseIncomingXml,
  requireEnv,
  asNumber,
  getByteLength,
  markdownToWecomText,
  splitWecomText,
} from "./utils.js";

const execFileAsync = promisify(execFile);
const xmlBuilder = new XMLBuilder({ ignoreAttributes: false });

// 请求体大小限制 (1MB)
const MAX_REQUEST_BODY_SIZE = 1024 * 1024;

function readRequestBody(req, maxSize = MAX_REQUEST_BODY_SIZE) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;

    req.on("data", (c) => {
      const chunk = Buffer.isBuffer(c) ? c : Buffer.from(c);
      totalSize += chunk.length;
      if (totalSize > maxSize) {
        reject(new Error(`Request body too large (limit: ${maxSize} bytes)`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// 企业微信 access_token 缓存（支持多账户）
const accessTokenCaches = new Map(); // key: corpId, value: { token, expiresAt, refreshPromise }

async function getWecomAccessToken({ corpId, corpSecret, cacheKey: customCacheKey }) {
  const cacheKey = customCacheKey || corpId;
  let cache = accessTokenCaches.get(cacheKey);

  if (!cache) {
    cache = { token: null, expiresAt: 0, refreshPromise: null };
    accessTokenCaches.set(cacheKey, cache);
  }

  const now = Date.now();
  if (cache.token && cache.expiresAt > now + 60000) {
    return cache.token;
  }

  // 如果已有刷新在进行中，等待它完成
  if (cache.refreshPromise) {
    return cache.refreshPromise;
  }

  cache.refreshPromise = (async () => {
    try {
      const tokenUrl = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(corpId)}&corpsecret=${encodeURIComponent(corpSecret)}`;
      const tokenRes = await fetch(tokenUrl);
      const tokenJson = await tokenRes.json();
      if (!tokenJson?.access_token) {
        throw new Error(`WeCom gettoken failed: ${JSON.stringify(tokenJson)}`);
      }

      cache.token = tokenJson.access_token;
      cache.expiresAt = Date.now() + (tokenJson.expires_in || 7200) * 1000;

      return cache.token;
    } finally {
      cache.refreshPromise = null;
    }
  })();

  return cache.refreshPromise;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// 简单的限流器，防止触发企业微信 API 限流
class RateLimiter {
  constructor({ maxConcurrent = 3, minInterval = 200 }) {
    this.maxConcurrent = maxConcurrent;
    this.minInterval = minInterval;
    this.running = 0;
    this.queue = [];
    this.lastExecution = 0;
  }

  async execute(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ fn, resolve, reject });
      this.processQueue();
    });
  }

  async processQueue() {
    if (this.running >= this.maxConcurrent || this.queue.length === 0) {
      return;
    }

    const now = Date.now();
    const waitTime = Math.max(0, this.lastExecution + this.minInterval - now);

    if (waitTime > 0) {
      setTimeout(() => this.processQueue(), waitTime);
      return;
    }

    this.running++;
    this.lastExecution = Date.now();

    const { fn, resolve, reject } = this.queue.shift();

    try {
      const result = await fn();
      resolve(result);
    } catch (err) {
      reject(err);
    } finally {
      this.running--;
      this.processQueue();
    }
  }
}

// API 调用限流器（最多3并发，200ms间隔）
const apiLimiter = new RateLimiter({ maxConcurrent: 3, minInterval: 200 });

// 消息处理限流器（最多5并发）
const messageProcessLimiter = new RateLimiter({ maxConcurrent: 5, minInterval: 0 });

// 发送单条文本消息（内部函数，带限流）
async function sendWecomTextSingle({ corpId, corpSecret, agentId, toUser, text }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });

    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "text",
      agentid: agentId,
      text: { content: text },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom message/send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送文本消息（支持自动分段）
async function sendWecomText({ corpId, corpSecret, agentId, toUser, text, logger }) {
  const chunks = splitWecomText(text);

  logger?.info?.(`wecom: splitting message into ${chunks.length} chunks, total bytes=${getByteLength(text)}`);

  for (let i = 0; i < chunks.length; i++) {
    logger?.info?.(`wecom: sending chunk ${i + 1}/${chunks.length}, bytes=${getByteLength(chunks[i])}`);
    await sendWecomTextSingle({ corpId, corpSecret, agentId, toUser, text: chunks[i] });
    // 分段发送时添加间隔，避免触发限流
    if (i < chunks.length - 1) {
      await sleep(300);
    }
  }
}

// 上传临时素材到企业微信
async function uploadWecomMedia({ corpId, corpSecret, type, buffer, filename, cacheKey }) {
  const accessToken = await getWecomAccessToken({ corpId, corpSecret, cacheKey });
  const uploadUrl = `https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=${encodeURIComponent(accessToken)}&type=${encodeURIComponent(type)}`;

  // 构建 multipart/form-data
  const boundary = "----WecomMediaUpload" + Date.now();
  const header = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="media"; filename="${filename}"\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([header, buffer, footer]);

  const res = await fetch(uploadUrl, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
    },
    body,
  });

  const json = await res.json();
  if (json.errcode !== 0) {
    throw new Error(`WeCom media upload failed: ${JSON.stringify(json)}`);
  }

  return json.media_id;
}

// 发送图片消息（带限流）
async function sendWecomImage({ corpId, corpSecret, agentId, toUser, mediaId }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;

    const body = {
      touser: toUser,
      msgtype: "image",
      agentid: agentId,
      image: { media_id: mediaId },
      safe: 0,
    };

    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom image send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送视频消息（带限流）
async function sendWecomVideo({ corpId, corpSecret, agentId, toUser, mediaId, title, description }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "video",
      agentid: agentId,
      video: {
        media_id: mediaId,
        ...(title ? { title } : {}),
        ...(description ? { description } : {}),
      },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom video send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送文件消息（带限流）
async function sendWecomFile({ corpId, corpSecret, agentId, toUser, mediaId }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "file",
      agentid: agentId,
      file: { media_id: mediaId },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom file send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 从 URL 下载媒体文件
async function fetchMediaFromUrl(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch media from URL: ${res.status}`);
  }
  const buffer = Buffer.from(await res.arrayBuffer());
  const contentType = res.headers.get("content-type") || "application/octet-stream";
  return { buffer, contentType };
}

const WecomChannelPlugin = {
  id: "wecom",
  meta: {
    id: "wecom",
    label: "WeCom",
    selectionLabel: "WeCom (企业微信自建应用 + 微信客服)",
    docsPath: "/channels/wecom",
    blurb: "Enterprise WeChat internal app + customer service via callback + send API.",
    aliases: ["wework", "qiwei", "wxwork"],
  },
  capabilities: {
    chatTypes: ["direct", "group"],
    media: {
      inbound: true,
      outbound: true, // 阶段二完成：支持发送图片
    },
    markdown: true, // 阶段三完成：支持 Markdown 转换
  },
  config: {
    listAccountIds: (cfg) => Object.keys(cfg.channels?.wecom?.accounts ?? {}),
    resolveAccount: (cfg, accountId) =>
      (cfg.channels?.wecom?.accounts?.[accountId ?? "default"] ?? { accountId }),
  },
  outbound: {
    deliveryMode: "direct",
    resolveTarget: ({ to }) => {
      const trimmed = to?.trim();
      if (!trimmed) return { ok: false, error: new Error("WeCom requires --to <UserId>") };
      return { ok: true, to: trimmed };
    },
    sendText: async ({ to, text }) => {
      const config = getWecomConfig();
      if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
        return { ok: false, error: new Error("WeCom not configured (check channels.wecom in clawdbot.json)") };
      }
      await sendWecomText({ corpId: config.corpId, corpSecret: config.corpSecret, agentId: config.agentId, toUser: to, text });
      return { ok: true, provider: "wecom" };
    },
  },
  // 入站消息处理 - clawdbot 会调用这个方法
  inbound: {
    // 当消息需要回复时，clawdbot 会调用这个方法
    deliverReply: async ({ to, text, accountId, mediaUrl, mediaType }) => {
      // 检测 KF 会话（to 格式: wecom-kf:openKfId:externalUserId）
      if (to.startsWith("wecom-kf:")) {
        const parts = to.split(":");
        const openKfId = parts[1];
        const externalUserId = parts.slice(2).join(":");
        const kfConfig = getWecomKfConfig();
        if (!kfConfig) throw new Error("WeCom KF not configured");
        const { corpId, kfSecret } = kfConfig;

        if (mediaUrl && mediaType === "image") {
          try {
            const { buffer } = await fetchMediaFromUrl(mediaUrl);
            const mediaId = await uploadWecomMedia({ corpId, corpSecret: kfSecret, type: "image", buffer, filename: "image.jpg", cacheKey: `${corpId}:kf` });
            await sendKfImage({ corpId, kfSecret, openKfId, toUser: externalUserId, mediaId });
          } catch (mediaErr) {
            console.warn?.(`wecom-kf: failed to send media: ${mediaErr.message}`);
          }
        }

        if (text) {
          await sendKfText({ corpId, kfSecret, openKfId, toUser: externalUserId, text });
        }

        return { ok: true };
      }

      // 原有应用消息逻辑
      const config = getWecomConfig();
      if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
        throw new Error("WeCom not configured (check channels.wecom in clawdbot.json)");
      }
      const { corpId, corpSecret, agentId } = config;
      // to 格式为 "wecom:userid"，需要提取 userid
      const userId = to.startsWith("wecom:") ? to.slice(6) : to;

      // 如果有媒体附件，先发送媒体
      if (mediaUrl && mediaType === "image") {
        try {
          const { buffer } = await fetchMediaFromUrl(mediaUrl);
          const mediaId = await uploadWecomMedia({
            corpId, corpSecret,
            type: "image",
            buffer,
            filename: "image.jpg",
          });
          await sendWecomImage({ corpId, corpSecret, agentId, toUser: userId, mediaId });
        } catch (mediaErr) {
          // 媒体发送失败不阻止文本发送，只记录警告
          console.warn?.(`wecom: failed to send media: ${mediaErr.message}`);
        }
      }

      // 发送文本消息
      if (text) {
        await sendWecomText({ corpId, corpSecret, agentId, toUser: userId, text });
      }

      return { ok: true };
    },
  },
};

// 存储 runtime 引用以便在消息处理中使用
let gatewayRuntime = null;

// 存储 gateway broadcast 上下文，用于向 Chat UI 广播消息
let gatewayBroadcastCtx = null;

// 写入消息到 session transcript 文件，使 Chat UI 可以显示
async function writeToTranscript({ sessionKey, role, text, logger }) {
  try {
    const stateDir = process.env.CLAWDBOT_STATE_DIR || join(homedir(), ".clawdbot");
    const sessionsDir = join(stateDir, "agents", "main", "sessions");
    const sessionsJsonPath = join(sessionsDir, "sessions.json");

    // 读取 sessions.json 获取 sessionId
    if (!existsSync(sessionsJsonPath)) {
      logger?.warn?.("wecom: sessions.json not found");
      return;
    }

    const { readFileSync } = await import("node:fs");
    const sessionsData = JSON.parse(readFileSync(sessionsJsonPath, "utf8"));
    const sessionEntry = sessionsData[sessionKey] || sessionsData[sessionKey.toLowerCase()];

    if (!sessionEntry?.sessionId) {
      logger?.warn?.(`wecom: session entry not found for ${sessionKey}`);
      return;
    }

    const transcriptPath = sessionEntry.sessionFile || join(sessionsDir, `${sessionEntry.sessionId}.jsonl`);

    const now = Date.now();
    const messageId = randomUUID().slice(0, 8);

    const transcriptEntry = {
      type: "message",
      id: messageId,
      timestamp: new Date(now).toISOString(),
      message: {
        role,
        content: [{ type: "text", text }],
        timestamp: now,
        stopReason: role === "assistant" ? "end_turn" : undefined,
        usage: role === "assistant" ? { input: 0, output: 0, totalTokens: 0 } : undefined,
      },
    };

    appendFileSync(transcriptPath, `${JSON.stringify(transcriptEntry)}\n`, "utf-8");
    logger?.info?.(`wecom: wrote ${role} message to transcript`);
  } catch (err) {
    logger?.warn?.(`wecom: failed to write transcript: ${err.message}`);
  }
}

// 广播消息到 Chat UI
function broadcastToChatUI({ sessionKey, role, text, runId, state }) {
  if (!gatewayBroadcastCtx) {
    return; // 没有 broadcast 上下文，跳过
  }

  try {
    const chatPayload = {
      runId: runId || `wecom-${Date.now()}`,
      sessionKey,
      seq: 0,
      state: state || "final",
      message: {
        role: role || "user",
        content: [{ type: "text", text: text || "" }],
        timestamp: Date.now(),
      },
    };

    gatewayBroadcastCtx.broadcast("chat", chatPayload);
    gatewayBroadcastCtx.bridgeSendToSession(sessionKey, "chat", chatPayload);
  } catch (err) {
    // 忽略广播错误，不影响主流程
  }
}

// 多账户配置存储
const wecomAccounts = new Map(); // key: accountId, value: config
let defaultAccountId = "default";

// 获取 wecom 配置（支持多账户）
// 优先级: channels.wecom > env.vars > 进程环境变量
function getWecomConfig(api, accountId = null) {
  const targetAccountId = accountId || defaultAccountId;

  // 如果已缓存，直接返回
  if (wecomAccounts.has(targetAccountId)) {
    return wecomAccounts.get(targetAccountId);
  }

  const cfg = api?.config ?? gatewayRuntime?.config;

  // 1. 优先从 channels.wecom 读取配置
  const channelConfig = cfg?.channels?.wecom;
  if (channelConfig && targetAccountId === "default") {
    const corpId = channelConfig.corpId;
    const corpSecret = channelConfig.corpSecret;
    const agentId = channelConfig.agentId;
    const callbackToken = channelConfig.callbackToken;
    const callbackAesKey = channelConfig.callbackAesKey;
    const webhookPath = channelConfig.webhookPath || "/wecom/callback";

    if (corpId && corpSecret && agentId) {
      const config = {
        accountId: targetAccountId,
        corpId,
        corpSecret,
        agentId: asNumber(agentId),
        callbackToken,
        callbackAesKey,
        webhookPath,
        enabled: channelConfig.enabled !== false,
      };
      wecomAccounts.set(targetAccountId, config);
      return config;
    }
  }

  // 2. 多账户支持：从 channels.wecom.accounts 读取
  const accountConfig = cfg?.channels?.wecom?.accounts?.[targetAccountId];
  if (accountConfig) {
    const corpId = accountConfig.corpId;
    const corpSecret = accountConfig.corpSecret;
    const agentId = accountConfig.agentId;
    const callbackToken = accountConfig.callbackToken;
    const callbackAesKey = accountConfig.callbackAesKey;
    const webhookPath = accountConfig.webhookPath || "/wecom/callback";

    if (corpId && corpSecret && agentId) {
      const config = {
        accountId: targetAccountId,
        corpId,
        corpSecret,
        agentId: asNumber(agentId),
        callbackToken,
        callbackAesKey,
        webhookPath,
        enabled: accountConfig.enabled !== false,
      };
      wecomAccounts.set(targetAccountId, config);
      return config;
    }
  }

  // 3. 回退到 env.vars（兼容旧配置）
  const envVars = cfg?.env?.vars ?? {};
  const accountPrefix = targetAccountId === "default" ? "WECOM" : `WECOM_${targetAccountId.toUpperCase()}`;

  let corpId = envVars[`${accountPrefix}_CORP_ID`] || (targetAccountId === "default" ? envVars.WECOM_CORP_ID : null);
  let corpSecret = envVars[`${accountPrefix}_CORP_SECRET`] || (targetAccountId === "default" ? envVars.WECOM_CORP_SECRET : null);
  let agentId = envVars[`${accountPrefix}_AGENT_ID`] || (targetAccountId === "default" ? envVars.WECOM_AGENT_ID : null);
  let callbackToken = envVars[`${accountPrefix}_CALLBACK_TOKEN`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_TOKEN : null);
  let callbackAesKey = envVars[`${accountPrefix}_CALLBACK_AES_KEY`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_AES_KEY : null);
  let webhookPath = envVars[`${accountPrefix}_WEBHOOK_PATH`] || (targetAccountId === "default" ? envVars.WECOM_WEBHOOK_PATH : null) || "/wecom/callback";

  // 4. 最后回退到进程环境变量
  if (!corpId) corpId = requireEnv(`${accountPrefix}_CORP_ID`) || requireEnv("WECOM_CORP_ID");
  if (!corpSecret) corpSecret = requireEnv(`${accountPrefix}_CORP_SECRET`) || requireEnv("WECOM_CORP_SECRET");
  if (!agentId) agentId = requireEnv(`${accountPrefix}_AGENT_ID`) || requireEnv("WECOM_AGENT_ID");
  if (!callbackToken) callbackToken = requireEnv(`${accountPrefix}_CALLBACK_TOKEN`) || requireEnv("WECOM_CALLBACK_TOKEN");
  if (!callbackAesKey) callbackAesKey = requireEnv(`${accountPrefix}_CALLBACK_AES_KEY`) || requireEnv("WECOM_CALLBACK_AES_KEY");

  if (corpId && corpSecret && agentId) {
    const config = {
      accountId: targetAccountId,
      corpId,
      corpSecret,
      agentId: asNumber(agentId),
      callbackToken,
      callbackAesKey,
      webhookPath,
    };
    wecomAccounts.set(targetAccountId, config);
    return config;
  }

  return null;
}

// 列出所有已配置的账户ID
function listWecomAccountIds(api) {
  const cfg = api?.config ?? gatewayRuntime?.config;
  const accountIds = new Set(["default"]);

  // 1. 从 channels.wecom.accounts 读取
  const channelAccounts = cfg?.channels?.wecom?.accounts;
  if (channelAccounts) {
    for (const accountId of Object.keys(channelAccounts)) {
      accountIds.add(accountId);
    }
  }

  // 2. 从 env.vars 读取 (兼容旧配置)
  const envVars = cfg?.env?.vars ?? {};
  for (const key of Object.keys(envVars)) {
    const match = key.match(/^WECOM_([A-Z0-9]+)_CORP_ID$/);
    if (match && match[1] !== "CORP") {
      accountIds.add(match[1].toLowerCase());
    }
  }

  return Array.from(accountIds);
}

// ============================================================
// 微信客服 (Customer Service) API 支持
// ============================================================

// KF 配置缓存
const wecomKfConfigs = new Map();

function getWecomKfConfig(api) {
  if (wecomKfConfigs.has("default")) {
    return wecomKfConfigs.get("default");
  }

  const cfg = api?.config ?? gatewayRuntime?.config;
  const wecomConfig = cfg?.channels?.wecom;
  const kfConfig = wecomConfig?.kf;

  // corpId 共享自父级 wecom 配置
  const corpId = wecomConfig?.corpId
    || cfg?.env?.vars?.WECOM_CORP_ID
    || requireEnv("WECOM_CORP_ID");

  const kfSecret = kfConfig?.kfSecret
    || cfg?.env?.vars?.WECOM_KF_SECRET
    || requireEnv("WECOM_KF_SECRET");

  const openKfId = kfConfig?.openKfId
    || cfg?.env?.vars?.WECOM_KF_OPEN_KFID
    || requireEnv("WECOM_KF_OPEN_KFID");

  const webhookPath = kfConfig?.webhookPath
    || cfg?.env?.vars?.WECOM_KF_WEBHOOK_PATH
    || "/wecom/kf/callback";

  const enabled = kfConfig?.enabled !== false;

  if (corpId && kfSecret && openKfId) {
    const config = { corpId, kfSecret, openKfId, webhookPath, enabled };
    wecomKfConfigs.set("default", config);
    return config;
  }

  return null;
}

// KF 通用消息发送
async function sendKfMessage({ corpId, kfSecret, openKfId, toUser, msgtype, content, logger }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({
      corpId,
      corpSecret: kfSecret,
      cacheKey: `${corpId}:kf`,
    });

    const url = `https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      open_kfid: openKfId,
      msgid: randomUUID(),
      msgtype,
      ...content,
    };

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const json = await res.json();
    if (json.errcode !== 0) {
      throw new Error(`KF send_msg failed: ${JSON.stringify(json)}`);
    }
    return json;
  });
}

// KF 文本发送（支持自动分段）
async function sendKfText({ corpId, kfSecret, openKfId, toUser, text, logger }) {
  const chunks = splitWecomText(text);
  logger?.info?.(`wecom-kf: splitting message into ${chunks.length} chunks`);

  for (let i = 0; i < chunks.length; i++) {
    await sendKfMessage({
      corpId, kfSecret, openKfId, toUser,
      msgtype: "text",
      content: { text: { content: chunks[i] } },
      logger,
    });
    if (i < chunks.length - 1) await sleep(300);
  }
}

// KF 图片发送
async function sendKfImage({ corpId, kfSecret, openKfId, toUser, mediaId }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "image",
    content: { image: { media_id: mediaId } },
  });
}

// KF 语音发送
async function sendKfVoice({ corpId, kfSecret, openKfId, toUser, mediaId }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "voice",
    content: { voice: { media_id: mediaId } },
  });
}

// KF 视频发送
async function sendKfVideo({ corpId, kfSecret, openKfId, toUser, mediaId }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "video",
    content: { video: { media_id: mediaId } },
  });
}

// KF 文件发送
async function sendKfFile({ corpId, kfSecret, openKfId, toUser, mediaId }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "file",
    content: { file: { media_id: mediaId } },
  });
}

// KF 链接发送
async function sendKfLink({ corpId, kfSecret, openKfId, toUser, title, desc, url, thumbMediaId }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "link",
    content: { link: { title, desc, url, thumb_media_id: thumbMediaId } },
  });
}

// KF 小程序发送
async function sendKfMiniprogram({ corpId, kfSecret, openKfId, toUser, appid, title, thumbMediaId, pagepath }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "miniprogram",
    content: { miniprogram: { appid, title, thumb_media_id: thumbMediaId, pagepath } },
  });
}

// KF 菜单消息发送
async function sendKfMsgmenu({ corpId, kfSecret, openKfId, toUser, headContent, list, tailContent }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "msgmenu",
    content: { msgmenu: { head_content: headContent, list, tail_content: tailContent } },
  });
}

// KF 位置消息发送
async function sendKfLocation({ corpId, kfSecret, openKfId, toUser, latitude, longitude, name, address }) {
  return sendKfMessage({
    corpId, kfSecret, openKfId, toUser,
    msgtype: "location",
    content: { location: { latitude, longitude, name, address } },
  });
}

// KF 命令处理
async function handleKfCommand({ api, config, openKfId, externalUserId, commandKey }) {
  const { corpId, kfSecret } = config;

  if (commandKey === "/help") {
    await sendKfText({
      corpId, kfSecret, openKfId, toUser: externalUserId,
      text: `🤖 AI 客服助手使用帮助\n\n可用命令：\n/help - 显示此帮助信息\n/clear - 清除会话历史\n/status - 查看系统状态\n\n直接发送消息即可与 AI 对话。\n支持发送图片，AI 会分析图片内容。`,
    });
  } else if (commandKey === "/clear") {
    const sessionId = `wecom-kf:${openKfId}:${externalUserId}`.toLowerCase();
    try {
      await execFileAsync("clawdbot", ["session", "clear", "--session-id", sessionId], { timeout: 10000 });
      await sendKfText({ corpId, kfSecret, openKfId, toUser: externalUserId, text: "✅ 会话已清除，我们可以开始新的对话了！" });
    } catch {
      await sendKfText({ corpId, kfSecret, openKfId, toUser: externalUserId, text: "会话已重置，请开始新的对话。" });
    }
  } else if (commandKey === "/status") {
    await sendKfText({
      corpId, kfSecret, openKfId, toUser: externalUserId,
      text: `📊 系统状态\n\n渠道：微信客服 (WeCom KF)\n会话ID：wecom-kf:${openKfId}:${externalUserId}\n客服账号：${openKfId}\n插件版本：0.4.0\n\n功能状态：\n✅ 文本消息\n✅ 图片发送/接收\n✅ 消息分段 (2048字符)\n✅ 命令系统\n✅ Markdown 转换\n✅ API 限流`,
    });
  }
}

// KF 入站消息处理
async function processKfInboundMessage({ api, config, msg, openKfId }) {
  const { corpId, kfSecret } = config;
  const kfCacheKey = `${corpId}:kf`;
  const externalUserId = msg.external_userid;
  const msgType = msg.msgtype;
  const sessionId = `wecom-kf:${openKfId}:${externalUserId}`.toLowerCase();

  api.logger.info?.(`wecom-kf: processing ${msgType} from ${externalUserId} in session ${sessionId}`);

  let messageText = "";
  let imageTempPath = null;

  try {
    // 消息类型处理
    switch (msgType) {
      case "text":
        messageText = msg.text?.content || "";
        break;

      case "image":
        if (msg.image?.media_id) {
          try {
            const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret: kfSecret, mediaId: msg.image.media_id, cacheKey: kfCacheKey });
            const ext = (contentType || "").includes("png") ? "png" : "jpg";
            const tempDir = join(tmpdir(), "clawdbot-wecom-kf");
            await mkdir(tempDir, { recursive: true });
            imageTempPath = join(tempDir, `image-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`);
            await writeFile(imageTempPath, buffer);
            messageText = `[客户发送了一张图片，已保存到: ${imageTempPath}]\n\n请使用 Read 工具查看这张图片并描述内容。`;
          } catch (err) {
            api.logger.warn?.(`wecom-kf: failed to download image: ${err.message}`);
            messageText = "[客户发送了一张图片，但下载失败]\n\n请告诉客户图片处理暂时不可用。";
          }
        }
        break;

      case "voice":
        if (msg.voice?.media_id) {
          messageText = "[客户发送了一条语音消息]\n\n请告诉客户目前暂不支持语音消息，建议发送文字消息。";
        }
        break;

      case "video":
        if (msg.video?.media_id) {
          try {
            const { buffer } = await downloadWecomMedia({ corpId, corpSecret: kfSecret, mediaId: msg.video.media_id, cacheKey: kfCacheKey });
            const tempDir = join(tmpdir(), "clawdbot-wecom-kf");
            await mkdir(tempDir, { recursive: true });
            const videoPath = join(tempDir, `video-${Date.now()}-${Math.random().toString(36).slice(2)}.mp4`);
            await writeFile(videoPath, buffer);
            messageText = `[客户发送了一个视频文件，已保存到: ${videoPath}]\n\n请告知客户您已收到视频。`;
          } catch (err) {
            api.logger.warn?.(`wecom-kf: failed to download video: ${err.message}`);
            messageText = "[客户发送了一个视频，但下载失败]\n\n请告诉客户视频处理暂时不可用。";
          }
        }
        break;

      case "file":
        if (msg.file?.media_id) {
          try {
            const { buffer } = await downloadWecomMedia({ corpId, corpSecret: kfSecret, mediaId: msg.file.media_id, cacheKey: kfCacheKey });
            const fileName = msg.file.file_name || `file-${Date.now()}.bin`;
            const tempDir = join(tmpdir(), "clawdbot-wecom-kf");
            await mkdir(tempDir, { recursive: true });
            const filePath = join(tempDir, `${Date.now()}-${fileName}`);
            await writeFile(filePath, buffer);
            const readableTypes = [".txt", ".md", ".json", ".xml", ".csv", ".log", ".pdf"];
            const isReadable = readableTypes.some(t => fileName.toLowerCase().endsWith(t));
            messageText = isReadable
              ? `[客户发送了一个文件: ${fileName}，已保存到: ${filePath}]\n\n请使用 Read 工具查看这个文件的内容。`
              : `[客户发送了一个文件: ${fileName}，大小: ${msg.file.file_size || buffer.length} 字节，已保存到: ${filePath}]\n\n请告知客户您已收到文件。`;
          } catch (err) {
            api.logger.warn?.(`wecom-kf: failed to download file: ${err.message}`);
            messageText = `[客户发送了一个文件${msg.file?.file_name ? `: ${msg.file.file_name}` : ""}，但下载失败]\n\n请告诉客户文件处理暂时不可用。`;
          }
        }
        break;

      case "link":
        messageText = `[客户分享了一个链接]\n标题: ${msg.link?.title || "(无标题)"}\n描述: ${msg.link?.desc || "(无描述)"}\n链接: ${msg.link?.url || "(无链接)"}\n\n请根据链接内容回复客户。如需要，可以使用 WebFetch 工具获取链接内容。`;
        break;

      case "location":
        messageText = `[客户发送了位置]\n名称: ${msg.location?.name || ""}\n地址: ${msg.location?.address || ""}\n经纬度: ${msg.location?.latitude},${msg.location?.longitude}`;
        break;

      case "business_card":
        messageText = `[客户发送了名片: ${msg.business_card?.userid || "unknown"}]`;
        break;

      case "miniprogram":
        messageText = `[客户发送了小程序]\n标题: ${msg.miniprogram?.title || ""}\nAppId: ${msg.miniprogram?.appid || ""}`;
        break;

      case "msgmenu":
        messageText = msg.msgmenu?.head_content || "[客户点击了菜单]";
        break;

      case "channels_shop_product":
        messageText = `[客户发送了视频号商品]\n商品ID: ${msg.channels_shop_product?.product_id || ""}`;
        break;

      case "channels_shop_order":
        messageText = `[客户发送了视频号订单]\n订单ID: ${msg.channels_shop_order?.order_id || ""}`;
        break;

      case "merged_msg":
        messageText = "[客户发送了合并转发消息]";
        break;

      default:
        api.logger.info?.(`wecom-kf: ignoring unsupported message type=${msgType}`);
        return;
    }

    // 命令处理
    if (msgType === "text" && messageText.startsWith("/")) {
      const commandKey = messageText.split(/\s+/)[0].toLowerCase();
      if (COMMANDS[commandKey]) {
        await handleKfCommand({ api, config, openKfId, externalUserId, commandKey });
        return;
      }
    }

    if (!messageText) return;

    // AI 调度（复用现有 runtime API）
    const cfg = api.config;
    const runtime = api.runtime;

    const route = runtime.channel.routing.resolveAgentRoute({
      cfg,
      sessionKey: sessionId,
      channel: "wecom-kf",
      accountId: "kf-default",
    });

    const storePath = runtime.channel.session.resolveStorePath(cfg.session?.store, {
      agentId: route.agentId,
    });

    const envelopeOptions = runtime.channel.reply.resolveEnvelopeFormatOptions(cfg);
    const body = runtime.channel.reply.formatInboundEnvelope({
      channel: "WeCom-KF",
      from: externalUserId,
      timestamp: msg.send_time * 1000,
      body: messageText,
      chatType: "direct",
      sender: { name: externalUserId, id: externalUserId },
      ...envelopeOptions,
    });

    const ctxPayload = {
      Body: body,
      RawBody: messageText,
      From: `wecom-kf:${openKfId}:${externalUserId}`,
      To: `wecom-kf:${externalUserId}`,
      SessionKey: sessionId,
      AccountId: "kf-default",
      ChatType: "direct",
      ConversationLabel: externalUserId,
      SenderName: externalUserId,
      SenderId: externalUserId,
      Provider: "wecom-kf",
      Surface: "wecom-kf",
      MessageSid: `wecom-kf-${msg.msgid}`,
      Timestamp: msg.send_time * 1000,
      OriginatingChannel: "wecom-kf",
      OriginatingTo: `wecom-kf:${externalUserId}`,
    };

    await runtime.channel.session.recordInboundSession({
      storePath,
      sessionKey: sessionId,
      ctx: ctxPayload,
      updateLastRoute: {
        sessionKey: sessionId,
        channel: "wecom-kf",
        to: externalUserId,
        accountId: "kf-default",
      },
      onRecordError: (err) => api.logger.warn?.(`wecom-kf: session record error: ${err}`),
    });

    runtime.channel.activity.record({
      channel: "wecom-kf",
      accountId: "kf-default",
      direction: "inbound",
    });

    await writeToTranscript({ sessionKey: sessionId, role: "user", text: messageText, logger: api.logger });
    broadcastToChatUI({ sessionKey: sessionId, role: "user", text: messageText, runId: `wecom-kf-in-${Date.now()}`, state: "final" });

    const outboundRunId = `wecom-kf-out-${Date.now()}`;
    await runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
      ctx: ctxPayload,
      cfg,
      dispatcherOptions: {
        deliver: async (payload, info) => {
          if (payload.text) {
            const formattedReply = markdownToWecomText(payload.text);
            await sendKfText({
              corpId, kfSecret, openKfId, toUser: externalUserId,
              text: formattedReply, logger: api.logger,
            });

            await writeToTranscript({ sessionKey: sessionId, role: "assistant", text: payload.text, logger: api.logger });
            broadcastToChatUI({
              sessionKey: sessionId, role: "assistant", text: payload.text,
              runId: outboundRunId, state: info.kind === "final" ? "final" : "streaming",
            });
          }
        },
        onError: (err, info) => {
          api.logger.error?.(`wecom-kf: ${info.kind} reply failed: ${String(err)}`);
        },
      },
      replyOptions: { disableBlockStreaming: true },
    });
  } catch (err) {
    api.logger.error?.(`wecom-kf: failed to process message: ${err.message}`);
    api.logger.error?.(`wecom-kf: stack trace: ${err.stack}`);

    try {
      await sendKfText({
        corpId, kfSecret, openKfId, toUser: externalUserId,
        text: `抱歉，处理您的消息时出现错误，请稍后重试。\n错误: ${err.message?.slice(0, 100) || "未知错误"}`,
        logger: api.logger,
      });
    } catch (sendErr) {
      api.logger.error?.(`wecom-kf: failed to send error message: ${sendErr.message}`);
    }
  } finally {
    if (imageTempPath) {
      unlink(imageTempPath).catch(() => {});
    }
  }
}

export default function register(api) {
  // 保存 runtime 引用
  gatewayRuntime = api.runtime;

  // 初始化配置
  const cfg = getWecomConfig(api);
  if (cfg) {
    api.logger.info?.(`wecom: config loaded (corpId=${cfg.corpId?.slice(0, 8)}...)`);
  } else {
    api.logger.warn?.("wecom: no configuration found (check channels.wecom in clawdbot.json)");
  }

  api.registerChannel({ plugin: WecomChannelPlugin });

  // 注册一个 gateway 方法来获取 broadcast 上下文
  // 这个方法会在插件加载时被调用，用于捕获 broadcast 上下文
  api.registerGatewayMethod("wecom.init", async (ctx, nodeId, params) => {
    gatewayBroadcastCtx = ctx;
    api.logger.info?.("wecom: gateway broadcast context captured");
    return { ok: true };
  });

  // 注册一个 gateway 方法用于广播消息到 Chat UI
  api.registerGatewayMethod("wecom.broadcast", async (ctx, nodeId, params) => {
    const { sessionKey, runId, message, state } = params || {};
    if (!sessionKey || !message) {
      return { ok: false, error: { message: "missing sessionKey or message" } };
    }

    const chatPayload = {
      runId: runId || `wecom-${Date.now()}`,
      sessionKey,
      seq: 0,
      state: state || "final",
      message: {
        role: message.role || "user",
        content: [{ type: "text", text: message.text || "" }],
        timestamp: Date.now(),
      },
    };

    ctx.broadcast("chat", chatPayload);
    ctx.bridgeSendToSession(sessionKey, "chat", chatPayload);

    // 保存 broadcast 上下文供后续使用
    gatewayBroadcastCtx = ctx;

    return { ok: true };
  });

  const webhookPath = cfg?.webhookPath || "/wecom/callback";
  const normalizedPath = normalizePluginHttpPath(webhookPath, "/wecom/callback") ?? "/wecom/callback";

  api.registerHttpRoute({
    path: normalizedPath,
    handler: async (req, res) => {
      const config = getWecomConfig(api);
      const token = config?.callbackToken;
      const aesKey = config?.callbackAesKey;

      const url = new URL(req.url ?? "/", "http://localhost");
      const msg_signature = url.searchParams.get("msg_signature") ?? "";
      const timestamp = url.searchParams.get("timestamp") ?? "";
      const nonce = url.searchParams.get("nonce") ?? "";
      const echostr = url.searchParams.get("echostr") ?? "";

      // Health check
      if (req.method === "GET" && !echostr) {
        res.statusCode = token && aesKey ? 200 : 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(token && aesKey ? "wecom webhook ok" : "wecom webhook not configured");
        return;
      }

      if (!token || !aesKey) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("WeCom plugin not configured (missing token/aesKey)");
        return;
      }

      if (req.method === "GET") {
        // URL verification
        const expected = computeMsgSignature({ token, timestamp, nonce, encrypt: echostr });
        if (!msg_signature || expected !== msg_signature) {
          res.statusCode = 401;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end("Invalid signature");
          return;
        }
        const { msg: plainEchostr } = decryptWecom({ aesKey, cipherTextBase64: echostr });
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(plainEchostr);
        return;
      }

      if (req.method !== "POST") {
        res.statusCode = 405;
        res.setHeader("Allow", "GET, POST");
        res.end();
        return;
      }

      const rawXml = await readRequestBody(req);
      const incoming = parseIncomingXml(rawXml);
      const encrypt = incoming?.Encrypt;
      if (!encrypt) {
        res.statusCode = 400;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("Missing Encrypt");
        return;
      }

      const expected = computeMsgSignature({ token, timestamp, nonce, encrypt });
      if (!msg_signature || expected !== msg_signature) {
        res.statusCode = 401;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("Invalid signature");
        return;
      }

      // ACK quickly (WeCom expects fast response within 5 seconds)
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("success");

      const { msg: decryptedXml } = decryptWecom({ aesKey, cipherTextBase64: encrypt });
      const msgObj = parseIncomingXml(decryptedXml);

      // 检测是否为群聊消息
      // 企业微信群聊消息会有 ChatId 字段（外部群）或通过应用消息接收
      const chatId = msgObj.ChatId || null;
      const isGroupChat = !!chatId;

      api.logger.info?.(
        `wecom inbound: FromUserName=${msgObj?.FromUserName} MsgType=${msgObj?.MsgType} ChatId=${chatId || "N/A"} Content=${(msgObj?.Content ?? "").slice?.(0, 80)}`
      );

      const fromUser = msgObj.FromUserName;
      const msgType = msgObj.MsgType;

      // 异步处理消息，不阻塞响应
      if (msgType === "text" && msgObj?.Content) {
        processInboundMessage({ api, fromUser, content: msgObj.Content, msgType: "text", chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async message processing failed: ${err.message}`);
        });
      } else if (msgType === "image" && msgObj?.MediaId) {
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "image", picUrl: msgObj.PicUrl, chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async image processing failed: ${err.message}`);
        });
      } else if (msgType === "voice" && msgObj?.MediaId) {
        // Recognition 字段包含企业微信自动语音识别的结果（需要在企业微信后台开启）
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "voice", recognition: msgObj.Recognition, chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async voice processing failed: ${err.message}`);
        });
      } else if (msgType === "video" && msgObj?.MediaId) {
        processInboundMessage({
          api, fromUser,
          mediaId: msgObj.MediaId,
          msgType: "video",
          thumbMediaId: msgObj.ThumbMediaId,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async video processing failed: ${err.message}`);
        });
      } else if (msgType === "file" && msgObj?.MediaId) {
        processInboundMessage({
          api, fromUser,
          mediaId: msgObj.MediaId,
          msgType: "file",
          fileName: msgObj.FileName,
          fileSize: msgObj.FileSize,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async file processing failed: ${err.message}`);
        });
      } else if (msgType === "link") {
        // 链接分享消息
        processInboundMessage({
          api, fromUser,
          msgType: "link",
          linkTitle: msgObj.Title,
          linkDescription: msgObj.Description,
          linkUrl: msgObj.Url,
          linkPicUrl: msgObj.PicUrl,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async link processing failed: ${err.message}`);
        });
      } else {
        api.logger.info?.(`wecom: ignoring unsupported message type=${msgType}`);
      }
    },
  });

  api.logger.info?.(`wecom: registered webhook at ${normalizedPath}`);

  // ============================================================
  // 微信客服 (KF) 回调注册
  // gateway 已处理 sync_msg 拉取，直接推送原始 JSON 消息到此路由
  // ============================================================
  const kfCfg = getWecomKfConfig(api);
  if (kfCfg?.enabled) {
    const kfWebhookPath = kfCfg.webhookPath || "/wecom/kf/callback";
    const normalizedKfPath = normalizePluginHttpPath(kfWebhookPath, "/wecom/kf/callback") ?? "/wecom/kf/callback";

    api.registerHttpRoute({
      path: normalizedKfPath,
      handler: async (req, res) => {
        const config = getWecomKfConfig(api);

        // Health check
        if (req.method === "GET") {
          res.statusCode = config ? 200 : 500;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end(config ? "wecom kf webhook ok" : "wecom kf webhook not configured");
          return;
        }

        if (req.method !== "POST") {
          res.statusCode = 405;
          res.setHeader("Allow", "GET, POST");
          res.end();
          return;
        }

        if (!config) {
          res.statusCode = 500;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end("WeCom KF not configured");
          return;
        }

        // 读取 gateway 推送的 sync_msg 原始 JSON 数据
        const rawBody = await readRequestBody(req);
        let msg;
        try {
          msg = JSON.parse(rawBody);
        } catch (parseErr) {
          res.statusCode = 400;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end("Invalid JSON");
          return;
        }

        // 立即 ACK
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ errcode: 0, errmsg: "ok" }));

        const openKfId = msg.open_kfid || config.openKfId;

        api.logger.info?.(
          `wecom-kf inbound: external_userid=${msg.external_userid} msgtype=${msg.msgtype} open_kfid=${openKfId}`
        );

        // 仅处理客户消息 (origin=3)，忽略系统消息和客服消息
        if (msg.origin !== undefined && msg.origin !== 3) {
          api.logger.info?.(`wecom-kf: ignoring non-customer message origin=${msg.origin}`);
          return;
        }

        // 异步处理消息
        processKfInboundMessage({ api, config, msg, openKfId }).catch(err => {
          api.logger.error?.(`wecom-kf: message processing failed: ${err.message}`);
        });
      },
    });

    api.logger.info?.(`wecom-kf: registered webhook at ${normalizedKfPath} (openKfId=${kfCfg.openKfId})`);
  } else {
    api.logger.info?.("wecom-kf: customer service API not configured or disabled");
  }
}

// 下载企业微信媒体文件
async function downloadWecomMedia({ corpId, corpSecret, mediaId, cacheKey }) {
  const accessToken = await getWecomAccessToken({ corpId, corpSecret, cacheKey });
  const mediaUrl = `https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token=${encodeURIComponent(accessToken)}&media_id=${encodeURIComponent(mediaId)}`;

  const res = await fetch(mediaUrl);
  if (!res.ok) {
    throw new Error(`Failed to download media: ${res.status}`);
  }

  const contentType = res.headers.get("content-type") || "";

  // 如果返回 JSON，说明有错误
  if (contentType.includes("application/json")) {
    const json = await res.json();
    throw new Error(`WeCom media download failed: ${JSON.stringify(json)}`);
  }

  const buffer = await res.arrayBuffer();
  return {
    buffer: Buffer.from(buffer),
    contentType,
  };
}

// 命令处理函数
async function handleHelpCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const helpText = `🤖 AI 助手使用帮助

可用命令：
/help - 显示此帮助信息
/clear - 清除会话历史，开始新对话
/status - 查看系统状态

直接发送消息即可与 AI 对话。
支持发送图片，AI 会分析图片内容。`;

  await sendWecomText({ corpId, corpSecret, agentId, toUser: fromUser, text: helpText });
  return true;
}

async function handleClearCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const sessionId = `wecom:${fromUser}`;
  try {
    await execFileAsync("clawdbot", ["session", "clear", "--session-id", sessionId], {
      timeout: 10000,
    });
    await sendWecomText({
      corpId, corpSecret, agentId, toUser: fromUser,
      text: "✅ 会话已清除，我们可以开始新的对话了！",
    });
  } catch (err) {
    api.logger.warn?.(`wecom: failed to clear session: ${err.message}`);
    await sendWecomText({
      corpId, corpSecret, agentId, toUser: fromUser,
      text: "会话已重置，请开始新的对话。",
    });
  }
  return true;
}

async function handleStatusCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const config = getWecomConfig(api);
  const accountIds = listWecomAccountIds(api);

  const statusText = `📊 系统状态

渠道：企业微信 (WeCom)
会话ID：wecom:${fromUser}
账户ID：${config?.accountId || "default"}
已配置账户：${accountIds.join(", ")}
插件版本：0.4.0

功能状态：
✅ 文本消息
✅ 图片发送/接收
✅ 消息分段 (2048字符)
✅ 命令系统
✅ Markdown 转换
✅ API 限流
✅ 多账户支持`;

  await sendWecomText({ corpId, corpSecret, agentId, toUser: fromUser, text: statusText });
  return true;
}

const COMMANDS = {
  "/help": handleHelpCommand,
  "/clear": handleClearCommand,
  "/status": handleStatusCommand,
};

// 异步处理入站消息 - 使用 gateway 内部 agent runtime API
async function processInboundMessage({ api, fromUser, content, msgType, mediaId, picUrl, recognition, thumbMediaId, fileName, fileSize, linkTitle, linkDescription, linkUrl, linkPicUrl, chatId, isGroupChat }) {
  const config = getWecomConfig(api);
  const cfg = api.config;
  const runtime = api.runtime;

  if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
    api.logger.warn?.("wecom: not configured (check channels.wecom in clawdbot.json)");
    return;
  }

  const { corpId, corpSecret, agentId } = config;

  try {
    // 会话ID：群聊使用 wecom:group:chatId，私聊使用 wecom:userId
    // 注意：sessionKey 需要统一为小写，与 resolveAgentRoute 保持一致
    const sessionId = isGroupChat ? `wecom:group:${chatId}`.toLowerCase() : `wecom:${fromUser}`.toLowerCase();
    api.logger.info?.(`wecom: processing ${msgType} message for session ${sessionId}${isGroupChat ? " (group)" : ""}`);

    // 命令检测（仅对文本消息）
    if (msgType === "text" && content?.startsWith("/")) {
      const commandKey = content.split(/\s+/)[0].toLowerCase();
      const handler = COMMANDS[commandKey];
      if (handler) {
        api.logger.info?.(`wecom: handling command ${commandKey}`);
        await handler({ api, fromUser, corpId, corpSecret, agentId, chatId, isGroupChat });
        return; // 命令已处理，不再调用 AI
      }
    }

    let messageText = content || "";

    // 处理图片消息 - 真正的 Vision 能力
    let imageBase64 = null;
    let imageMimeType = null;

    if (msgType === "image" && mediaId) {
      api.logger.info?.(`wecom: downloading image mediaId=${mediaId}`);

      try {
        // 优先使用 mediaId 下载原图
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        imageBase64 = buffer.toString("base64");
        imageMimeType = contentType || "image/jpeg";
        messageText = "[用户发送了一张图片]";
        api.logger.info?.(`wecom: image downloaded, size=${buffer.length} bytes, type=${imageMimeType}`);
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download image via mediaId: ${downloadErr.message}`);

        // 降级：尝试通过 PicUrl 下载
        if (picUrl) {
          try {
            const { buffer, contentType } = await fetchMediaFromUrl(picUrl);
            imageBase64 = buffer.toString("base64");
            imageMimeType = contentType || "image/jpeg";
            messageText = "[用户发送了一张图片]";
            api.logger.info?.(`wecom: image downloaded via PicUrl, size=${buffer.length} bytes`);
          } catch (picUrlErr) {
            api.logger.warn?.(`wecom: failed to download image via PicUrl: ${picUrlErr.message}`);
            messageText = "[用户发送了一张图片，但下载失败]\n\n请告诉用户图片处理暂时不可用。";
          }
        } else {
          messageText = "[用户发送了一张图片，但下载失败]\n\n请告诉用户图片处理暂时不可用。";
        }
      }
    }

    // 处理语音消息
    if (msgType === "voice" && mediaId) {
      api.logger.info?.(`wecom: received voice message mediaId=${mediaId}`);

      // 企业微信开启语音识别后，Recognition 字段会包含转写结果
      if (recognition) {
        api.logger.info?.(`wecom: voice recognition result: ${recognition.slice(0, 50)}...`);
        messageText = `[语音消息] ${recognition}`;
      } else {
        // 没有开启语音识别，提示用户
        messageText = "[用户发送了一条语音消息]\n\n请告诉用户目前暂不支持语音消息，建议发送文字消息。";
      }
    }

    // 处理视频消息
    if (msgType === "video" && mediaId) {
      api.logger.info?.(`wecom: received video message mediaId=${mediaId}`);
      try {
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        const videoTempPath = join(tempDir, `video-${Date.now()}-${Math.random().toString(36).slice(2)}.mp4`);
        await writeFile(videoTempPath, buffer);
        api.logger.info?.(`wecom: saved video to ${videoTempPath}, size=${buffer.length} bytes`);
        messageText = `[用户发送了一个视频文件，已保存到: ${videoTempPath}]\n\n请告知用户您已收到视频。`;
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download video: ${downloadErr.message}`);
        messageText = "[用户发送了一个视频，但下载失败]\n\n请告诉用户视频处理暂时不可用。";
      }
    }

    // 处理文件消息
    if (msgType === "file" && mediaId) {
      api.logger.info?.(`wecom: received file message mediaId=${mediaId}, fileName=${fileName}, size=${fileSize}`);
      try {
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        const ext = fileName ? fileName.split('.').pop() : 'bin';
        const safeFileName = fileName || `file-${Date.now()}.${ext}`;
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        const fileTempPath = join(tempDir, `${Date.now()}-${safeFileName}`);
        await writeFile(fileTempPath, buffer);
        api.logger.info?.(`wecom: saved file to ${fileTempPath}, size=${buffer.length} bytes`);

        const readableTypes = ['.txt', '.md', '.json', '.xml', '.csv', '.log', '.pdf'];
        const isReadable = readableTypes.some(t => safeFileName.toLowerCase().endsWith(t));

        if (isReadable) {
          messageText = `[用户发送了一个文件: ${safeFileName}，已保存到: ${fileTempPath}]\n\n请使用 Read 工具查看这个文件的内容。`;
        } else {
          messageText = `[用户发送了一个文件: ${safeFileName}，大小: ${fileSize || buffer.length} 字节，已保存到: ${fileTempPath}]\n\n请告知用户您已收到文件。`;
        }
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download file: ${downloadErr.message}`);
        messageText = `[用户发送了一个文件${fileName ? `: ${fileName}` : ''}，但下载失败]\n\n请告诉用户文件处理暂时不可用。`;
      }
    }

    // 处理链接分享消息
    if (msgType === "link") {
      api.logger.info?.(`wecom: received link message title=${linkTitle}, url=${linkUrl}`);
      messageText = `[用户分享了一个链接]\n标题: ${linkTitle || '(无标题)'}\n描述: ${linkDescription || '(无描述)'}\n链接: ${linkUrl || '(无链接)'}\n\n请根据链接内容回复用户。如需要，可以使用 WebFetch 工具获取链接内容。`;
    }

    if (!messageText) {
      api.logger.warn?.("wecom: empty message content");
      return;
    }

    // 如果有图片，保存到临时文件供 AI 读取
    let imageTempPath = null;
    if (imageBase64 && imageMimeType) {
      try {
        const ext = imageMimeType.includes("png") ? "png" : imageMimeType.includes("gif") ? "gif" : "jpg";
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        imageTempPath = join(tempDir, `image-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`);
        await writeFile(imageTempPath, Buffer.from(imageBase64, "base64"));
        api.logger.info?.(`wecom: saved image to ${imageTempPath}`);
        // 更新消息文本，告知 AI 图片位置
        messageText = `[用户发送了一张图片，已保存到: ${imageTempPath}]\n\n请使用 Read 工具查看这张图片并描述内容。`;
      } catch (saveErr) {
        api.logger.warn?.(`wecom: failed to save image: ${saveErr.message}`);
        messageText = "[用户发送了一张图片，但保存失败]\n\n请告诉用户图片处理暂时不可用。";
        imageTempPath = null;
      }
    }

    // 获取路由信息
    const route = runtime.channel.routing.resolveAgentRoute({
      cfg,
      sessionKey: sessionId,
      channel: "wecom",
      accountId: config.accountId || "default",
    });

    // 获取 storePath
    const storePath = runtime.channel.session.resolveStorePath(cfg.session?.store, {
      agentId: route.agentId,
    });

    // 格式化消息体
    const envelopeOptions = runtime.channel.reply.resolveEnvelopeFormatOptions(cfg);
    const body = runtime.channel.reply.formatInboundEnvelope({
      channel: "WeCom",
      from: fromUser,
      timestamp: Date.now(),
      body: messageText,
      chatType: isGroupChat ? "group" : "direct",
      sender: {
        name: fromUser,
        id: fromUser,
      },
      ...envelopeOptions,
    });

    // 构建 Session 上下文对象
    const ctxPayload = {
      Body: body,
      RawBody: content || "",
      From: isGroupChat ? `wecom:group:${chatId}` : `wecom:${fromUser}`,
      To: `wecom:${fromUser}`,
      SessionKey: sessionId,
      AccountId: config.accountId || "default",
      ChatType: isGroupChat ? "group" : "direct",
      ConversationLabel: fromUser,
      SenderName: fromUser,
      SenderId: fromUser,
      Provider: "wecom",
      Surface: "wecom",
      MessageSid: `wecom-${Date.now()}`,
      Timestamp: Date.now(),
      OriginatingChannel: "wecom",
      OriginatingTo: `wecom:${fromUser}`,
    };

    // 注册会话到 Sessions UI
    await runtime.channel.session.recordInboundSession({
      storePath,
      sessionKey: sessionId,
      ctx: ctxPayload,
      updateLastRoute: !isGroupChat ? {
        sessionKey: sessionId,
        channel: "wecom",
        to: fromUser,
        accountId: config.accountId || "default",
      } : undefined,
      onRecordError: (err) => {
        api.logger.warn?.(`wecom: failed to record session: ${err}`);
      },
    });
    api.logger.info?.(`wecom: session registered for ${sessionId}`);

    // 记录渠道活动
    runtime.channel.activity.record({
      channel: "wecom",
      accountId: config.accountId || "default",
      direction: "inbound",
    });

    // 写入用户消息到 transcript 文件（使 Chat UI 可以显示历史）
    await writeToTranscript({
      sessionKey: sessionId,
      role: "user",
      text: messageText,
      logger: api.logger,
    });

    // 广播用户消息到 Chat UI
    const inboundRunId = `wecom-inbound-${Date.now()}`;
    broadcastToChatUI({
      sessionKey: sessionId,
      role: "user",
      text: messageText,
      runId: inboundRunId,
      state: "final",
    });

    api.logger.info?.(`wecom: dispatching message via agent runtime for session ${sessionId}`);

    // 使用 gateway 内部 agent runtime API 调用 AI
    // 对标 Telegram 的 dispatchReplyWithBufferedBlockDispatcher
    const chunkMode = runtime.channel.text.resolveChunkMode(cfg, "wecom", config.accountId || "default");
    const tableMode = runtime.channel.text.resolveMarkdownTableMode({
      cfg,
      channel: "wecom",
      accountId: config.accountId || "default",
    });

    try {
      const outboundRunId = `wecom-outbound-${Date.now()}`;
      await runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
        ctx: ctxPayload,
        cfg,
        dispatcherOptions: {
          deliver: async (payload, info) => {
            // 发送回复到企业微信
            if (payload.text) {
              api.logger.info?.(`wecom: delivering ${info.kind} reply, length=${payload.text.length}`);
              // 应用 Markdown 转换
              const formattedReply = markdownToWecomText(payload.text);
              await sendWecomText({
                corpId,
                corpSecret,
                agentId,
                toUser: fromUser,
                text: formattedReply,
                logger: api.logger,
              });
              api.logger.info?.(`wecom: sent AI reply to ${fromUser}: ${formattedReply.slice(0, 50)}...`);

              // 写入 AI 回复到 transcript 文件（使 Chat UI 可以显示历史）
              await writeToTranscript({
                sessionKey: sessionId,
                role: "assistant",
                text: payload.text,
                logger: api.logger,
              });

              // 广播 AI 回复到 Chat UI
              broadcastToChatUI({
                sessionKey: sessionId,
                role: "assistant",
                text: payload.text,
                runId: outboundRunId,
                state: info.kind === "final" ? "final" : "streaming",
              });
            }
          },
          onError: (err, info) => {
            api.logger.error?.(`wecom: ${info.kind} reply failed: ${String(err)}`);
          },
        },
        replyOptions: {
          // 禁用流式响应，因为企业微信不支持编辑消息
          disableBlockStreaming: true,
        },
      });
    } finally {
      // 清理临时图片文件
      if (imageTempPath) {
        unlink(imageTempPath).catch(() => {});
      }
    }

  } catch (err) {
    api.logger.error?.(`wecom: failed to process message: ${err.message}`);
    api.logger.error?.(`wecom: stack trace: ${err.stack}`);

    // 发送错误提示给用户
    try {
      await sendWecomText({
        corpId,
        corpSecret,
        agentId,
        toUser: fromUser,
        text: `抱歉，处理您的消息时出现错误，请稍后重试。\n错误: ${err.message?.slice(0, 100) || "未知错误"}`,
        logger: api.logger,
      });
    } catch (sendErr) {
      api.logger.error?.(`wecom: failed to send error message: ${sendErr.message}`);
      api.logger.error?.(`wecom: send error stack: ${sendErr.stack}`);
      api.logger.error?.(`wecom: original error was: ${err.message}`);
    }
  }
}
