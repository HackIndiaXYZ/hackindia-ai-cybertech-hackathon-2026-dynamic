
const MAX_HISTORY = 100;

const getHostname = (value) => {
  try {
    let input = String(value || "").trim();

    if (!input) return null;

    if (!/^https?:\/\//i.test(input)) {
      input = `https://${input}`;
    }

    const parsed = new URL(input);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }

    return parsed.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
};

const getStoredData = async () => {
  const data = await chrome.storage.local.get([
    "threatHistory",
    "blockedDomains"
  ]);

  return {
    threatHistory: Array.isArray(data.threatHistory)
      ? data.threatHistory
      : [],
    blockedDomains: Array.isArray(data.blockedDomains)
      ? data.blockedDomains
      : []
  };
};

const saveScanResult = async (result) => {
  const { threatHistory } = await getStoredData();

  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    url: String(result.url || ""),
    hostname: getHostname(result.url) || "",
    score: Number(result.score ?? result.riskScore ?? 0),
    risk: String(result.risk || result.level || "Unknown"),
    reasons: Array.isArray(result.reasons) ? result.reasons : [],
    timestamp: new Date().toISOString()
  };

  threatHistory.unshift(entry);

  await chrome.storage.local.set({
    threatHistory: threatHistory.slice(0, MAX_HISTORY)
  });

  return entry;
};

const getBlockedDomains = async () => {
  const { blockedDomains } = await getStoredData();
  return blockedDomains;
};

const blockWebsite = async (value) => {
  const hostname = getHostname(value);

  if (!hostname) {
    throw new Error("Please enter a valid website URL.");
  }

  const { blockedDomains } = await getStoredData();

  if (blockedDomains.includes(hostname)) {
    return {
      success: true,
      message: "Website is already blocked.",
      hostname
    };
  }

  const existingRules =
    await chrome.declarativeNetRequest.getDynamicRules();

  const nextRuleId = Math.max(
    1000,
    ...existingRules.map((rule) => rule.id)
  ) + 1;

  const escapedHostname = hostname.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

  const rule = {
    id: nextRuleId,
    priority: 1,
    action: {
      type: "block"
    },
    condition: {
      regexFilter: `^https?://([a-z0-9-]+\\.)*${escapedHostname}([/:?#]|$)`,
      resourceTypes: ["main_frame"]
    }
  };

  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [rule]
  });

  blockedDomains.push(hostname);

  await chrome.storage.local.set({
    blockedDomains
  });

  return {
    success: true,
    message: "Website blocked successfully.",
    hostname
  };
};

const unblockWebsite = async (value) => {
  const hostname = getHostname(value);

  if (!hostname) {
    throw new Error("Please enter a valid website URL.");
  }

  const { blockedDomains } = await getStoredData();

  const matchingRules =
    await chrome.declarativeNetRequest.getDynamicRules();

  const rulesToRemove = matchingRules
    .filter((rule) => {
      const filter = rule.condition?.regexFilter || "";
      return filter.includes(hostname.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      ));
    })
    .map((rule) => rule.id);

  if (rulesToRemove.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rulesToRemove
    });
  }

  const updatedDomains = blockedDomains.filter(
    (domain) => domain !== hostname
  );

  await chrome.storage.local.set({
    blockedDomains: updatedDomains
  });

  return {
    success: true,
    message: "Website unblocked successfully.",
    hostname
  };
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handleMessage = async () => {
    switch (message?.type) {
      case "SAVE_SCAN_RESULT": {
        if (!message.result || typeof message.result !== "object") {
          throw new Error("Scan result is missing.");
        }

        const saved = await saveScanResult(message.result);

        return {
          success: true,
          result: saved
        };
      }

      case "GET_BLOCKED_DOMAINS": {
        return {
          success: true,
          blockedDomains: await getBlockedDomains()
        };
      }

      case "BLOCK_WEBSITE": {
        return await blockWebsite(
          message.url || message.domain || message.hostname
        );
      }

      case "UNBLOCK_WEBSITE": {
        return await unblockWebsite(
          message.url || message.domain || message.hostname
        );
      }

      case "GET_THREAT_HISTORY": {
        const { threatHistory } = await getStoredData();

        return {
          success: true,
          threatHistory
        };
      }

      case "CLEAR_THREAT_HISTORY": {
        await chrome.storage.local.set({
          threatHistory: []
        });

        return {
          success: true,
          message: "Threat history cleared."
        };
      }

      case "GET_PROTECTION_STATUS": {
        const { blockedDomains } = await getStoredData();

        return {
          success: true,
          enabled: true,
          blockedCount: blockedDomains.length
        };
      }

      default:
        return {
          success: false,
          message: "Unknown ThreatLens AI action."
        };
    }
  };

  handleMessage()
    .then(sendResponse)
    .catch((error) => {
      sendResponse({
        success: false,
        message: error?.message || "Something went wrong."
      });
    });

  return true;
});
