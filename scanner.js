
(function () {
  "use strict";

  function normalizeUrl(value) {
    let input = String(value || "").trim();

    if (!input) {
      throw new Error("Please enter a website URL.");
    }

    if (!/^https?:\/\//i.test(input)) {
      input = "https://" + input;
    }

    let parsed;

    try {
      parsed = new URL(input);
    } catch {
      throw new Error("Please enter a valid website URL.");
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only HTTP and HTTPS websites are supported.");
    }

    return parsed.href;
  }

  function scanUrl(value) {
    const url = normalizeUrl(value);
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    let score = 0;
    const reasons = [];

    const addRisk = (points, reason) => {
      score += points;
      reasons.push(reason);
    };

    if (parsed.protocol === "http:") {
      addRisk(15, "Website is using HTTP instead of HTTPS.");
    }

    if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
      addRisk(25, "Domain contains internationalized characters that may be used for impersonation.");
    }

    const suspiciousWords = [
      "login",
      "verify",
      "account",
      "secure",
      "update",
      "wallet",
      "password",
      "banking",
      "gift",
      "free"
    ];

    const foundWords = suspiciousWords.filter((word) =>
      hostname.split(/[.-]/).includes(word)
    );

    if (foundWords.length > 0) {
      addRisk(
        Math.min(foundWords.length * 8, 20),
        "Domain contains potentially suspicious keywords: " +
          foundWords.join(", ") +
          "."
      );
    }

    if (hostname.split(".").length >= 5) {
      addRisk(10, "Website uses an unusually deep subdomain structure.");
    }

    if (hostname.length > 45) {
      addRisk(10, "Domain name is unusually long.");
    }

    if (parsed.username || parsed.password) {
      addRisk(25, "URL contains embedded username or password information.");
    }

    const riskyExtensions = [
      ".zip",
      ".mov",
      ".click",
      ".top",
      ".work"
    ];

    if (riskyExtensions.some((extension) => hostname.endsWith(extension))) {
      addRisk(10, "Domain uses an extension sometimes associated with suspicious websites.");
    }

    score = Math.min(score, 100);

    let risk = "Low";

    if (score >= 60) {
      risk = "High";
    } else if (score >= 30) {
      risk = "Medium";
    }

    if (reasons.length === 0) {
      reasons.push(
        "No suspicious patterns were detected by the local URL checks."
      );
    }

    return {
      url,
      hostname,
      score,
      risk,
      reasons,
      timestamp: new Date().toISOString()
    };
  }

  globalThis.ThreatLensScanner = {
    normalizeUrl,
    scanUrl
  };
})();
