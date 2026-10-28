
const BACKEND_URL = "http://127.0.0.1:8000";

const $ = (id) => document.getElementById(id);

let latestScan = null;

function showMessage(id, message) {
  const element = $(id);
  if (element) element.textContent = message;
}

function normalizeUrl(value) {
  return globalThis.ThreatLensScanner.normalizeUrl(value);
}

function getHostname(value) {
  try {
    return new URL(normalizeUrl(value)).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function sendBackgroundMessage(type, data = {}) {
  return chrome.runtime.sendMessage({ type, ...data });
}

async function callBackend(path, body) {
  const response = await fetch(`${BACKEND_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.detail || data.message || `Backend returned HTTP ${response.status}`
    );
  }

  return data;
}

function displayScanResult(result) {
  latestScan = result;

  $("result").style.display = "block";
  $("score").textContent = `${Number(result.score ?? 0)}/100`;
  $("risk").textContent = result.risk || "Unknown";
  $("resultUrl").textContent = result.url || "";
  $("reasons").replaceChildren();

  const reasons = Array.isArray(result.reasons)
    ? result.reasons
    : ["No additional details provided."];

  reasons.forEach((reason) => {
    const item = document.createElement("p");
    item.textContent = `• ${String(reason)}`;
    $("reasons").appendChild(item);
  });
}

async function scanWebsite() {
  showMessage("actionMessage", "");

  try {
    const url = normalizeUrl($("website").value);
    $("website").value = url;

    const localResult = globalThis.ThreatLensScanner.scanUrl(url);
    let finalResult = { ...localResult };

    showMessage("actionMessage", "Scanning website and checking backend...");

    try {
      const backendResult = await callBackend("/api/analyze", { url });

      finalResult = {
        ...finalResult,
        score: Number(backendResult.score ?? backendResult.riskScore ?? finalResult.score),
        risk: backendResult.risk || backendResult.level || finalResult.risk,
        reasons: Array.isArray(backendResult.reasons)
          ? backendResult.reasons
          : finalResult.reasons
      };
    } catch (error) {
      showMessage(
        "actionMessage",
        `Local scan completed. Backend analysis unavailable: ${error.message}`
      );
    }

    try {
      const aiResult = await callBackend("/api/ai-analyze", {
        url,
        score: finalResult.score,
        risk: finalResult.risk,
        reasons: finalResult.reasons
      });

      const explanation =
        aiResult.explanation ||
        aiResult.analysis ||
        aiResult.message;

      if (explanation) {
        finalResult.reasons = [
          ...finalResult.reasons,
          `AI analysis: ${String(explanation)}`
        ];
      }
    } catch (error) {
      showMessage(
        "actionMessage",
        `Scan completed; AI explanation unavailable: ${error.message}`
      );
    }

    displayScanResult(finalResult);

    try {
      await sendBackgroundMessage("SAVE_SCAN_RESULT", {
        result: finalResult
      });
    } catch (error) {
      showMessage(
        "actionMessage",
        `Scan finished, but history could not be saved: ${error.message}`
      );
    }

    if (!["High", "Medium", "Low"].includes(finalResult.risk)) {
      finalResult.risk = "Unknown";
    }

    if (!latestScan) latestScan = finalResult;

    if (finalResult.risk === "High") {
      showMessage(
        "actionMessage",
        "High risk detected. Avoid entering passwords or sensitive information."
      );
    } else if (!$("actionMessage").textContent) {
      showMessage("actionMessage", "Scan completed.");
    }
  } catch (error) {
    showMessage("actionMessage", error.message || "Unable to scan this URL.");
  }
}

async function blockCurrentWebsite() {
  if (!latestScan?.url) {
    showMessage("actionMessage", "Scan a website first.");
    return;
  }

  try {
    const response = await sendBackgroundMessage("BLOCK_WEBSITE", {
      url: latestScan.url
    });

    if (!response?.success) {
      throw new Error(response?.message || "Could not block website.");
    }

    showMessage("actionMessage", response.message);
    await renderBlockedSites();
  } catch (error) {
    showMessage("actionMessage", error.message);
  }
}

async function unblockCurrentWebsite() {
  if (!latestScan?.url) {
    showMessage("actionMessage", "Scan a website first.");
    return;
  }

  try {
    const response = await sendBackgroundMessage("UNBLOCK_WEBSITE", {
      url: latestScan.url
    });

    if (!response?.success) {
      throw new Error(response?.message || "Could not unblock website.");
    }

    showMessage("actionMessage", response.message);
    await renderBlockedSites();
  } catch (error) {
    showMessage("actionMessage", error.message);
  }
}

async function renderBlockedSites() {
  const list = $("blockedSitesList");
  list.replaceChildren();

  try {
    const response = await sendBackgroundMessage("GET_BLOCKED_DOMAINS");

    if (!response?.success) {
      throw new Error(response?.message || "Could not load blocked websites.");
    }

    const domains = response.blockedDomains || [];

    if (domains.length === 0) {
      list.textContent = "No websites are currently blocked.";
      return;
    }

    domains.forEach((domain) => {
      const row = document.createElement("div");
      row.style.marginBottom = "10px";

      const name = document.createElement("div");
      name.textContent = domain;
      name.style.overflowWrap = "anywhere";

      const button = document.createElement("button");
      button.textContent = "Unblock";
      button.addEventListener("click", async () => {
        try {
          const result = await sendBackgroundMessage("UNBLOCK_WEBSITE", {
            domain
          });

          if (!result?.success) {
            throw new Error(result?.message || "Unblock failed.");
          }

          showMessage("blockedSitesMessage", result.message);
          await renderBlockedSites();
        } catch (error) {
          showMessage("blockedSitesMessage", error.message);
        }
      });

      row.append(name, button);
      list.appendChild(row);
    });
  } catch (error) {
    list.textContent = error.message;
  }
}

async function lookupWhois() {
  const input = $("website").value.trim();

  if (!input) {
    showMessage("whoisResult", "Enter a website URL first.");
    return;
  }

  showMessage("whoisResult", "Looking up domain registration information...");

  try {
    const data = await callBackend("/api/whois", {
      url: normalizeUrl(input)
    });

    $("whoisResult").textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    showMessage(
      "whoisResult",
      `Lookup failed: ${error.message}`
    );
  }
}

function reviewWebsite() {
  if (!latestScan?.url) {
    showMessage("actionMessage", "Scan a website first.");
    return;
  }

  const confirmed = confirm(
    `Open this website for manual review?\n\n${latestScan.url}\n\nThreatLens AI cannot guarantee that this website is safe.`
  );

  if (confirmed) {
    chrome.tabs.create({ url: latestScan.url });
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("scanButton").addEventListener("click", scanWebsite);
  $("blockButton").addEventListener("click", blockCurrentWebsite);
  $("allowButton").addEventListener("click", unblockCurrentWebsite);
  $("reviewButton").addEventListener("click", reviewWebsite);
  $("whoisButton").addEventListener("click", lookupWhois);

  $("historyButton").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
  });

  $("blockedSitesButton").addEventListener("click", async () => {
    const section = $("blockedSitesSection");
    section.style.display =
      section.style.display === "none" ? "block" : "none";

    if (section.style.display === "block") {
      await renderBlockedSites();
    }
  });

  $("website").addEventListener("keydown", (event) => {
    if (event.key === "Enter") scanWebsite();
  });

  try {
    const status = await sendBackgroundMessage("GET_PROTECTION_STATUS");

    if (status?.success) {
      $("protectionStatus").textContent =
        `● Protection Ready · ${status.blockedCount} site(s) blocked`;
    }
  } catch {
    showMessage(
      "actionMessage",
      "Could not connect to the background service. Check the extension."
    );
  }
});
