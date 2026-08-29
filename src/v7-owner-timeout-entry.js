import productionWorker from "./v7-production-entry.js";
import { clientIp } from "./engine/network.js";
import { deriveManualIpKey } from "./adaptive/manual-ip-block.js";
import { ownerLearningEnabled } from "./adaptive/owner-learning.js";
import {
  processOwnerLearningTimeouts,
  scheduleOwnerConfirmation,
} from "./adaptive/owner-learning-timeout.js";

function isMonitorSubmit(request) {
  try {
    const url = new URL(request.url);
    return request.method === "POST" && url.pathname === "/_shadow/v7-monitor-submit";
  } catch {
    return false;
  }
}

async function maybeArmOwnerTimeout(request, response, env) {
  if (!ownerLearningEnabled(env) || !isMonitorSubmit(request)) return;
  if (!env?.DB || !env?.CHALLENGE_SECRET) return;

  let data;
  try {
    data = await response.clone().json();
  } catch {
    return;
  }

  if (
    data?.owner_learning_buttons !== true ||
    data?.manual_ip_control_ready !== true ||
    data?.telegram_configured !== true ||
    !data?.event_id
  ) {
    return;
  }

  const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
  if (!ipKey) return;
  await scheduleOwnerConfirmation(env.DB, data.event_id, ipKey, Date.now());
}

export default {
  async fetch(request, env, ctx) {
    const response = await productionWorker.fetch(request, env, ctx);
    try {
      await maybeArmOwnerTimeout(request, response, env);
    } catch {}
    return response;
  },

  async scheduled(_controller, env, ctx) {
    const task = processOwnerLearningTimeouts(env, Date.now());
    if (ctx?.waitUntil) ctx.waitUntil(task);
    else await task;
  },
};
