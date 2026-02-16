/**
 * ============================================================================
 *  ScamurAI — Gmail Security Add-on (Frontend)
 * ============================================================================
 *
 *  Description:
 *  ScamurAI is a Gmail add-on that analyzes email messages and provides
 *  structured security insights including risk scoring, AI-based reasoning,
 *  link reputation checks, authentication analysis (SPF/DKIM/DMARC),
 *  and deterministic security signals.
 *
 *  The frontend is implemented using Google Apps Script and CardService.
 *  It is responsible for:
 *    • Rendering UI cards (Basic + Advanced modes)
 *    • Stable navigation 
 *    • Managing user settings and history (User Properties)
 *    • Displaying AI engine status and Safe Browsing metadata
 *    • Triggering backend analysis via HTTPS API
 *
 *  Architecture principles:
 *    • Snapshot-based analysis stability per messageId
 *    • Clear separation between UI rendering and analysis normalization
 *    • Deterministic refresh (only explicit Refresh re-runs analysis)
 *    • User-scoped settings and history storage
 *
 *  Author:
 *    Naor Daniel
 *
 *  Project:
 *    ScamurAI — AI-Driven Email Threat Analysis Add-on
 *
 *  Year:
 *    2026
 *
 *  Notes:
 *    This file contains UI construction, navigation logic, settings management,
 *    and integration with the ScamurAI backend service.
 *
 * ============================================================================
 */


const backendUrl = "https://scamurai-backend-aain.onrender.com/analyze";
const cacheTtlSeconds = 600;

const userSettingsKey = "scamuraiUserSettingsV1";
const historyKey = "scamuraiHistoryV1";
const maxHistoryItems = 50;

const analysisSnapshotKeyPrefix = "scamuraiAnalysisSnapshotV1:";

/* =====================================================================
 * Entry points
 * ===================================================================== */

function onGmailMessageOpen(event) {
  const message = loadMessageFromTrigger(event);
  const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
  return buildMainCard(message, analysis);
}

function onHomepage(event) {
  return buildHomepageCard();
}

/* =====================================================================
 * Navigation helpers
 * ===================================================================== */

function formatAnalyzedAt_(isoString) {
  try {
    const d = new Date(String(isoString || ""));
    if (isNaN(d.getTime())) return String(isoString || "");
    return Utilities.formatDate(d, Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm:ss");
  } catch (e) {
    return String(isoString || "");
  }
}

function getNavContext_(event) {
  const returnTo = getEventParameter(event, "returnTo") || "home";
  const messageId = getEventParameter(event, "messageId") || "";
  const infoKey = getEventParameter(event, "infoKey") || "";
  return { returnTo: returnTo, messageId: messageId, infoKey: infoKey };
}

function buildNavParams_(ctx) {
  return {
    returnTo: String((ctx && ctx.returnTo) || "home"),
    messageId: String((ctx && ctx.messageId) || ""),
    infoKey: String((ctx && ctx.infoKey) || "")
  };
}

function navigateBack(event) {
  const ctx = getNavContext_(event);

  if (ctx.returnTo === "main") {
    const message = ctx.messageId ? loadMessageById(ctx.messageId) : loadMessageFromTrigger(event);
    const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
    return buildMainCard(message, analysis);
  }

  if (ctx.returnTo === "technical") {
    const message = ctx.messageId ? loadMessageById(ctx.messageId) : loadMessageFromTrigger(event);
    const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
    return buildTechnicalDetailsCard(message, analysis);
  }

  if (ctx.returnTo === "settings") {
    return buildSettingsCard(ctx);
  }

  if (ctx.returnTo === "history") {
    return buildHistoryCard(ctx);
  }

  return buildHomepageCard();
}

/* =====================================================================
 * Homepage
 * ===================================================================== */

function buildHomepageCard() {
  const cardBuilder = CardService.newCardBuilder();
  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI")
      .setSubtitle("Controls and settings")
  );

  const section = CardService.newCardSection().setHeader("Menu");

  section.addWidget(
    CardService.newTextButton()
      .setText("Settings")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openSettings")
          .setParameters({ returnTo: "home", messageId: "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("History")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openHistory")
          .setParameters({ returnTo: "home", messageId: "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("Help")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openHelp")
          .setParameters({ returnTo: "home", messageId: "" })
      )
  );

  cardBuilder.addSection(section);
  return cardBuilder.build();
}

function openHelp(event) {
  const ctx = getNavContext_(event);
  return buildInfoCard({ infoKey: "helpMain", returnTo: ctx.returnTo || "home", messageId: ctx.messageId || "" });
}

/* =====================================================================
 * Message loading
 * ===================================================================== */

function loadMessageFromTrigger(event) {
  const messageId = event && event.gmail && event.gmail.messageId ? String(event.gmail.messageId) : "";
  if (!messageId) return createEmptyMessage("Missing messageId in trigger event.");
  return loadMessageById(messageId);
}

function loadMessageById(messageId) {
  const accessToken = ScriptApp.getOAuthToken();
  const url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + encodeURIComponent(messageId) + "?format=full";

  const response = UrlFetchApp.fetch(url, {
    method: "get",
    headers: { Authorization: "Bearer " + accessToken },
    muteHttpExceptions: true
  });

  const statusCode = response.getResponseCode();
  const responseText = response.getContentText() || "";

  if (statusCode !== 200) {
    return createEmptyMessage("Gmail API error " + statusCode + ": " + responseText.slice(0, 200), messageId);
  }

  const gmailMessage = JSON.parse(responseText);

  const subject = readHeader(gmailMessage, "Subject") || "(no subject)";
  const from = readHeader(gmailMessage, "From") || "(unknown sender)";
  const replyTo = readHeader(gmailMessage, "Reply-To") || "";
  const returnPath = readHeader(gmailMessage, "Return-Path") || "";
  const authenticationResults = readHeader(gmailMessage, "Authentication-Results") || "";

  const bodies = extractBodies(gmailMessage);
  const plainText = bodies.plainText || stripHtml(bodies.htmlText || "");

  const fromDomain = extractDomain(from);
  const replyToDomain = replyTo ? extractDomain(replyTo) : "";
  const returnPathDomain = returnPath ? extractDomain(returnPath) : "";

  const authentication = parseAuthenticationResults(authenticationResults);

  return {
    messageId: String(messageId),
    subject: String(subject),
    from: String(from),
    replyTo: String(replyTo),
    returnPath: String(returnPath),
    fromDomain: fromDomain,
    replyToDomain: replyToDomain,
    returnPathDomain: returnPathDomain,
    authentication: authentication,
    plainTextBody: plainText || "",
    debugMessage: ""
  };
}

function createEmptyMessage(debugMessage, messageId) {
  return {
    messageId: messageId || "",
    subject: "(no subject)",
    from: "(unknown sender)",
    replyTo: "",
    returnPath: "",
    fromDomain: "",
    replyToDomain: "",
    returnPathDomain: "",
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown" },
    plainTextBody: "",
    debugMessage: debugMessage || ""
  };
}

/* =====================================================================
 * Stable analysis snapshot (cache-first navigation)
 * ===================================================================== */

function getStableAnalysis_(messageId, messageOrNull, options) {
  const opts = options || {};
  const id = String(messageId || "");
  if (!id) return createErrorAnalysis("missingMessageId", "Missing messageId", "No messageId was provided.");

  if (opts.forceRefresh) {
    removeCachedAnalysis(id);
    removeAnalysisSnapshot_(id);
  }

  const snapshot = getAnalysisSnapshot_(id);
  if (snapshot) {
    snapshot.cached = true;
    return snapshot;
  }

  const message = messageOrNull && messageOrNull.messageId ? messageOrNull : loadMessageById(id);
  const analysis = analyzeMessageNetwork_(message);
  storeAnalysisSnapshot_(id, analysis);

  addHistoryItem(message, analysis);
  return analysis;
}

function getAnalysisSnapshot_(messageId) {
  const props = PropertiesService.getUserProperties();
  const raw = props.getProperty(analysisSnapshotKeyPrefix + String(messageId));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && parsed.analysis ? parsed.analysis : null;
  } catch (e) {
    return null;
  }
}

function storeAnalysisSnapshot_(messageId, analysis) {
  const props = PropertiesService.getUserProperties();
  const payload = {
    storedAt: new Date().toISOString(),
    analysis: analysis
  };
  props.setProperty(analysisSnapshotKeyPrefix + String(messageId), JSON.stringify(payload));
}

function removeAnalysisSnapshot_(messageId) {
  const props = PropertiesService.getUserProperties();
  props.deleteProperty(analysisSnapshotKeyPrefix + String(messageId));
}

/* =====================================================================
 * Analysis + caching + history
 * ===================================================================== */

function analyzeMessageNetwork_(message) {
  const messageId = message && message.messageId ? String(message.messageId) : "";
  const cacheKey = messageId ? buildCacheKey(messageId) : "";

  if (cacheKey) {
    const cachedValue = CacheService.getUserCache().get(cacheKey);
    if (cachedValue) {
      const cachedObject = JSON.parse(cachedValue);
      cachedObject.cached = true;
      return cachedObject;
    }
  }

  const userSettings = getUserSettings();

  const payload = {
    subject: message.subject || "",
    sender: message.from || "",
    body: message.plainTextBody || "",
    fromDomain: message.fromDomain || "",
    replyToDomain: message.replyToDomain || "",
    returnPathDomain: message.returnPathDomain || "",
    authentication: message.authentication || { spf: "unknown", dkim: "unknown", dmarc: "unknown" },
    settings: userSettings
  };

  try {
    const response = UrlFetchApp.fetch(backendUrl, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    });

    const statusCode = response.getResponseCode();
    const responseText = response.getContentText() || "";

    if (statusCode >= 200 && statusCode < 300) {
      const backendData = JSON.parse(responseText);
      const normalized = normalizeAnalysis(backendData);

      if (cacheKey) {
        CacheService.getUserCache().put(cacheKey, JSON.stringify(normalized), cacheTtlSeconds);
      }

      return normalized;
    }

    return createErrorAnalysis("backendError", "Backend error", "HTTP " + statusCode + ": " + responseText.slice(0, 200));
  } catch (error) {
    return createErrorAnalysis("backendUnreachable", "Backend unreachable", String(error));
  }
}

function normalizeAnalysis(data) {
  const ui = data && data.ui ? data.ui : {};
  const uiMeta = ui && ui.meta ? ui.meta : {};
  const uiAi = uiMeta && uiMeta.ai ? uiMeta.ai : {};
  const uiSafeBrowsing = uiMeta && uiMeta.safeBrowsing ? uiMeta.safeBrowsing : {};

  const analyzedAt = uiMeta && uiMeta.analyzedAt ? String(uiMeta.analyzedAt) : "";

  const aiStatus = uiAi && uiAi.status ? String(uiAi.status) : "";
  const aiReason = uiAi && uiAi.reason ? String(uiAi.reason) : "";
  const aiModelMeta = uiAi && uiAi.model ? String(uiAi.model) : "";
  const aiLatencyMsMeta = typeof uiAi.latencyMs === "number" ? uiAi.latencyMs : 0;

  const safeBrowsingStatus = uiSafeBrowsing && uiSafeBrowsing.status ? String(uiSafeBrowsing.status) : "";
  const safeBrowsingChecked = typeof uiSafeBrowsing.checkedCount === "number" ? uiSafeBrowsing.checkedCount : 0;
  const safeBrowsingMalicious = typeof uiSafeBrowsing.maliciousCount === "number" ? uiSafeBrowsing.maliciousCount : 0;
  const safeBrowsingError = uiSafeBrowsing && uiSafeBrowsing.error ? String(uiSafeBrowsing.error) : "";

  const reasons = Array.isArray(data && data.reasons) ? data.reasons : [];
  const signals = reasons.map(r => ({
    id: r && r.id ? String(r.id) : "signal",
    title: r && r.title ? String(r.title) : "Signal",
    points: r && typeof r.points === "number" ? r.points : 0,
    evidence: r && r.evidence ? String(r.evidence) : ""
  }));

  const breakdown = data && data.breakdown ? data.breakdown : null;
  const ai = data && data.ai ? data.ai : {};
  const keyFindings = ui && Array.isArray(ui.keyFindings) ? ui.keyFindings.map(String) : [];

  const risk = data && data.risk ? data.risk : {};
  const confidenceScore = typeof risk.confidenceScore === "number" ? risk.confidenceScore : 0;
  const confidenceRationale = Array.isArray(risk.confidenceRationale) ? risk.confidenceRationale.map(String) : [];

  const weights = risk.weights || { hard: 0.0, free: 0.0 };

  const finalAiStatus = aiStatus ? aiStatus.toLowerCase() : (risk && risk.aiAvailable ? "on" : "off");
  const finalAiAvailable = finalAiStatus === "on";

  const finalAiReason =
    aiReason ? aiReason :
    (ai && ai.statusReason ? String(ai.statusReason) :
    (ai && ai.error ? String(ai.error) : ""));

  return {
    verdict: data && data.verdict ? String(data.verdict) : "Unknown",
    score: data && typeof data.score === "number" ? data.score : 0,
    confidence: data && data.confidence ? String(data.confidence) : "",
    version: data && data.version ? String(data.version) : "",
    traceId: data && data.traceId ? String(data.traceId) : "",
    cached: !!(data && data.cached),

    analyzedAt: analyzedAt,

    keyFindings: keyFindings,
    recommendedAction: ui && ui.recommendedAction ? String(ui.recommendedAction) : "",

    signals: signals,
    breakdown: breakdown,

    aiSummary: ai.summary ? String(ai.summary) : "",
    aiThreatType: ai.threatType ? String(ai.threatType) : "",
    aiLatencyMs: typeof ai.latencyMs === "number" ? ai.latencyMs : aiLatencyMsMeta,
    aiError: ai.error ? String(ai.error) : "",
    aiModel: ai.model ? String(ai.model) : "",

    aiStatus: finalAiStatus,
    aiReason: finalAiReason,
    aiModelMeta: aiModelMeta,
    aiAvailable: finalAiAvailable,

    safeBrowsingStatus: safeBrowsingStatus,
    safeBrowsingChecked: safeBrowsingChecked,
    safeBrowsingMalicious: safeBrowsingMalicious,
    safeBrowsingError: safeBrowsingError,

    riskFinal: typeof risk.final === "number" ? risk.final : 0,
    riskHard: typeof risk.hard === "number" ? risk.hard : 0,
    riskFree: typeof risk.free === "number" ? risk.free : 0,
    riskWeights: weights,

    confidenceScore: confidenceScore,
    confidenceRationale: confidenceRationale
  };
}

function createErrorAnalysis(id, title, evidence) {
  return {
    verdict: "Error",
    score: 0,
    confidence: "",
    version: "",
    traceId: "",
    cached: false,

    analyzedAt: "",

    keyFindings: [],
    recommendedAction: "Unable to analyze. Verify manually before taking action.",
    signals: [{ id: id, title: title, points: 0, evidence: evidence }],
    breakdown: null,

    aiSummary: "",
    aiThreatType: "",
    aiLatencyMs: 0,
    aiError: String(evidence || ""),
    aiModel: "",

    aiStatus: "off",
    aiReason: String(evidence || ""),
    aiModelMeta: "",
    aiAvailable: false,

    safeBrowsingStatus: "",
    safeBrowsingChecked: 0,
    safeBrowsingMalicious: 0,
    safeBrowsingError: "",

    riskFinal: 0,
    riskHard: 0,
    riskFree: 0,
    riskWeights: { hard: 0.0, free: 0.0 },

    confidenceScore: 0,
    confidenceRationale: []
  };
}

/* =====================================================================
 * Triggers: refresh / cache clear / navigation
 * ===================================================================== */

function refreshAnalysis(event) {
  const messageId = getEventParameter(event, "messageId");
  if (!messageId) {
    const message = createEmptyMessage("Refresh failed: missing messageId.");
    const analysis = createErrorAnalysis("refreshMissingMessageId", "Refresh failed", "Missing messageId parameter.");
    return buildMainCard(message, analysis);
  }

  removeCachedAnalysis(messageId);
  removeAnalysisSnapshot_(messageId);

  const message = loadMessageById(messageId);
  const analysis = getStableAnalysis_(messageId, message, { forceRefresh: true });
  return buildMainCard(message, analysis);
}

function clearCache(event) {
  return refreshAnalysis(event);
}

function openWhyVerdict(event) {
  const messageId = getEventParameter(event, "messageId");
  const message = messageId ? loadMessageById(messageId) : loadMessageFromTrigger(event);
  const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
  return buildWhyVerdictCard_(message, analysis);
}

function showTechnicalDetails(event) {
  const messageId = getEventParameter(event, "messageId");
  const message = messageId ? loadMessageById(messageId) : loadMessageFromTrigger(event);
  const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
  return buildTechnicalDetailsCard(message, analysis);
}

function showMainView(event) {
  const messageId = getEventParameter(event, "messageId");
  const message = messageId ? loadMessageById(messageId) : loadMessageFromTrigger(event);
  const analysis = getStableAnalysis_(message.messageId, message, { forceRefresh: false });
  return buildMainCard(message, analysis);
}


/* =====================================================================
 * UI: main card
 * ===================================================================== */

function buildMainCard(message, analysis) {
  const cardBuilder = CardService.newCardBuilder();
  const settings = getUserSettings();
  const viewMode = settings.viewMode || "basic";

  const headerSubtitle = analysis.analyzedAt ? formatAnalyzedAt_(analysis.analyzedAt) : "";

  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI")
      .setSubtitle(headerSubtitle)
  );

  cardBuilder.addSection(buildSafetyScoreSection_(analysis, message));

  if (viewMode === "advanced") {
    cardBuilder.addSection(buildKeyFindingsSection_(analysis));
  }

  cardBuilder.addSection(buildRecommendedActionSection_(analysis));

  cardBuilder.addSection(buildAiStatusCompactSection_(analysis));

  if (viewMode === "advanced") {
    cardBuilder.addSection(buildSystemStatusSection_(analysis));
    cardBuilder.addSection(buildAdvancedSummarySection_(analysis));
  }

  cardBuilder.addSection(buildQuickActionsSection_(message));
  cardBuilder.addSection(buildMoreActionsSection_(message));
  cardBuilder.addSection(buildRefreshSection_(message));

  return cardBuilder.build();
}

function buildSafetyScoreSection_(analysis, message) {
  const section = CardService.newCardSection().setHeader("Safety");

  const verdict = analysis && analysis.verdict ? String(analysis.verdict) : "Unknown";
  const confidence = analysis && analysis.confidence ? String(analysis.confidence) : "";
  const score = (analysis && typeof analysis.score === "number") ? analysis.score : 0;

  const verdictColor =
    verdict === "Safe" ? "#1b5e20" :
    verdict === "Suspicious" ? "#ef6c00" :
    verdict === "Malicious" ? "#b71c1c" :
    "#424242";

  section.addWidget(
    CardService.newTextParagraph().setText(
      "<font size=\"4\"><b><font color=\"" + verdictColor + "\">" +
      escapeHtml(verdict.toUpperCase()) +
      "</font></b></font>"
    )
  );

  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>Safety score:</b> " + escapeHtml(String(score)) + "/100"
    )
  );

  const barHtml = makeBarHtml_(score, 14);
  section.addWidget(
    CardService.newTextParagraph().setText(barHtml)
  );

  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>Confidence (verdict):</b> " + escapeHtml(confidence || "Low")
    )
  );

  const topReasons = pickTopReasons_(analysis, 4);
  if (topReasons.length) {
    const lines = topReasons.map((x, idx) =>
      "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + escapeHtml(String(x))
    ).join("<br>");
    section.addWidget(CardService.newTextParagraph().setText(lines));
  }

  section.addWidget(
    CardService.newTextButton()
      .setText("Why this verdict?")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openWhyVerdict")
          .setParameters({ messageId: (message && message.messageId) ? String(message.messageId) : "" })
      )
  );

  return section;
}

function buildQuickEngineLineSection_(analysis) {
  const section = CardService.newCardSection();

  const status = analysis && analysis.aiStatus ? String(analysis.aiStatus).toLowerCase() : (analysis && analysis.aiAvailable ? "on" : "off");
  const isOn = status === "on";

  let line = "<b>AI:</b> " + (isOn ? "On" : "Off");

  if (isOn) {
    const model = analysis && (analysis.aiModelMeta || analysis.aiModel) ? String(analysis.aiModelMeta || analysis.aiModel) : "";
    if (model) line += " • " + escapeHtml(model);
  } else {
    const reason = sanitizeAiReason_(analysis && analysis.aiReason ? analysis.aiReason : "");
    if (reason) line += " — " + escapeHtml(reason);
  }

  section.addWidget(CardService.newTextParagraph().setText(line));
  return section;
}

function buildSystemStatusSection_(analysis) {
  const section = CardService.newCardSection().setHeader("System status");

  const status = analysis && analysis.aiStatus ? String(analysis.aiStatus).toLowerCase() : (analysis && analysis.aiAvailable ? "on" : "off");
  const isOn = status === "on";

  const model = analysis && analysis.aiModelMeta ? String(analysis.aiModelMeta) : (analysis && analysis.aiModel ? String(analysis.aiModel) : "");
  const latency = analysis && typeof analysis.aiLatencyMs === "number" ? analysis.aiLatencyMs : 0;

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("AI engine")
      .setContent(isOn ? "On" : "Off")
  );

  if (isOn) {
    if (model) section.addWidget(CardService.newKeyValue().setTopLabel("Model").setContent(model));
    if (latency) section.addWidget(CardService.newKeyValue().setTopLabel("Latency").setContent(String(latency) + "ms"));
  } else {
    const reason = sanitizeAiReason_(analysis && analysis.aiReason ? analysis.aiReason : "");
    if (reason) section.addWidget(CardService.newKeyValue().setTopLabel("Reason").setContent(reason));
  }

  if (analysis && analysis.safeBrowsingStatus) {
    const checked = typeof analysis.safeBrowsingChecked === "number" ? analysis.safeBrowsingChecked : 0;
    const malicious = typeof analysis.safeBrowsingMalicious === "number" ? analysis.safeBrowsingMalicious : 0;

    section.addWidget(
      CardService.newKeyValue()
        .setTopLabel("Safe Browsing")
        .setContent(String(analysis.safeBrowsingStatus))
    );

    section.addWidget(
      CardService.newKeyValue()
        .setTopLabel("Checked / flagged")
        .setContent(String(checked) + " / " + String(malicious))
    );

    if (analysis.safeBrowsingError) {
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel("Safe Browsing error")
          .setContent(String(analysis.safeBrowsingError))
      );
    }
  }

  return section;
}

function buildAdvancedSummarySection_(analysis) {
  const section = CardService.newCardSection().setHeader("Advanced summary");

  const signals = Array.isArray(analysis && analysis.signals) ? analysis.signals : [];
  if (!signals.length) {
    section.addWidget(CardService.newTextParagraph().setText("No signals recorded."));
    return section;
  }

  const top = signals
    .slice()
    .sort((a, b) => (b.points || 0) - (a.points || 0))
    .slice(0, 5);

  const lines = top.map((s, idx) => {
    const title = escapeHtml(String(s.title || "Signal"));
    const pts = escapeHtml(String(s.points || 0));
    const ev = s.evidence ? " — " + escapeHtml(String(s.evidence)) : "";
    return "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + title + " (" + pts + ")" + ev;
  }).join("<br>");

  section.addWidget(CardService.newTextParagraph().setText(lines));
  return section;
}

function buildKeyFindingsSection_(analysis) {
  const section = CardService.newCardSection().setHeader("Key findings");

  const items = Array.isArray(analysis.keyFindings) ? analysis.keyFindings : [];
  if (!items.length) {
    section.addWidget(CardService.newTextParagraph().setText("No meaningful risk indicators detected."));
    return section;
  }

  const top = items.slice(0, 4).map(x => String(x));
  const lines = top.map((x, idx) => "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + escapeHtml(x)).join("<br>");
  section.addWidget(CardService.newTextParagraph().setText(lines));
  return section;
}

function buildRecommendedActionSection_(analysis) {
  const section = CardService.newCardSection().setHeader("Recommended action");

  const text = analysis.recommendedAction
    ? analysis.recommendedAction
    : defaultRecommendationText_(analysis.verdict);

  section.addWidget(CardService.newTextParagraph().setText(escapeHtml(text)));
  return section;
}

function buildBasicSystemLineSection_(analysis) {
  const section = CardService.newCardSection();

  const status = analysis && analysis.aiStatus ? String(analysis.aiStatus).toLowerCase() : (analysis && analysis.aiAvailable ? "on" : "off");
  const isOn = status === "on";

  const label = isOn ? "AI: On" : "AI: Off";
  const reason = !isOn ? sanitizeAiReason_(analysis && analysis.aiReason ? analysis.aiReason : "") : "";
  const text = reason ? (label + " — " + reason) : label;

  section.addWidget(CardService.newTextParagraph().setText("<b>" + escapeHtml(text) + "</b>"));
  return section;
}

function buildShowDetailsSection_(message) {
  const section = CardService.newCardSection();

  section.addWidget(
    CardService.newTextButton()
      .setText("Show technical details")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("showTechnicalDetails")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  return section;
}

function buildQuickActionsSection_(message) {
  const section = CardService.newCardSection().setHeader("Quick actions");

  section.addWidget(
    CardService.newTextButton()
      .setText("Trust this domain")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("addDomainToAllowlist")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("Add to ScamurAI blocklist")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("addDomainToBlocklist")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  return section;
}

function buildMoreActionsSection_(message) {
  const section = CardService.newCardSection().setHeader("More");

  section.addWidget(
    CardService.newTextButton()
      .setText("Show technical details")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("showTechnicalDetails")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("Settings")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openSettings")
          .setParameters({ returnTo: "main", messageId: message.messageId || "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("History")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openHistory")
          .setParameters({ returnTo: "main", messageId: message.messageId || "" })
      )
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("Help")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openHelp")
          .setParameters({ returnTo: "main", messageId: message.messageId || "" })
      )
  );

  return section;
}

function buildRefreshSection_(message) {
  const section = CardService.newCardSection().setHeader("Refresh");

  section.addWidget(
    CardService.newTextButton()
      .setText("Refresh analysis")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("refreshAnalysis")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  return section;
}

function buildActionsSection_(message) {
  const sectionQuick = CardService.newCardSection().setHeader("Quick actions");

  sectionQuick.addWidget(
    CardService.newTextButton()
      .setText("Trust this domain")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("addDomainToAllowlist")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  sectionQuick.addWidget(
    CardService.newTextButton()
      .setText("Add to ScamurAI blocklist")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("addDomainToBlocklist")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  const sectionMore = CardService.newCardSection().setHeader("More");

  sectionMore.addWidget(
    CardService.newTextButton()
      .setText("Show technical details")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("showTechnicalDetails")
          .setParameters({ messageId: message.messageId || "" })
      )
  );

  sectionMore.addWidget(
    CardService.newTextButton()
      .setText("Settings")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openSettings")
          .setParameters({ returnTo: "main", messageId: message.messageId || "" })
      )
  );

  sectionMore.addWidget(
    CardService.newTextButton()
      .setText("History")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("openHistory")
          .setParameters({ returnTo: "main", messageId: message.messageId || "" })
      )
  );

  const sectionRefresh = CardService.newCardSection().setHeader("Refresh");

  sectionRefresh.addWidget(
    CardService.newTextButton()
      .setText("Refresh analysis")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("refreshAnalysis")
          .setParameters({ messageId: message.messageId || "" })
      )
  );
  return mergeSections_(sectionQuick, sectionMore, sectionRefresh);
}

function mergeSections_(a, b, c) {
  const section = CardService.newCardSection().setHeader("Actions");
  [a, b, c].forEach(sec => {
    const widgets = sec.getWidgets ? sec.getWidgets() : null;
  });
  return a;
}

function defaultRecommendationText_(verdict) {
  if (verdict === "Malicious") return "Do not click anything; report as phishing and verify via official channel.";
  if (verdict === "Suspicious") return "Verify sender and links before taking any action.";
  if (verdict === "Safe") return "No action needed; stay cautious with unexpected requests.";
  return "Unable to analyze reliably. Verify manually before taking action.";
}

/* =====================================================================
 * UI: technical details card
 * ===================================================================== */

function buildTechnicalDetailsCard(message, analysis) {
  const cardBuilder = CardService.newCardBuilder();

  const headerSubtitle =
    analysis.verdict + " • " + analysis.score + "/100"
    + (analysis.confidence ? " • " + analysis.confidence : "")
    + (analysis.cached ? " • Cached" : "");

  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI — Technical details")
      .setSubtitle(headerSubtitle)
  );

  cardBuilder.addSection(buildTechnicalAuthSection_(message));
  cardBuilder.addSection(buildTechnicalLinksSection_(analysis, message));
  cardBuilder.addSection(buildTechnicalConfidenceSection_(analysis, message));
  cardBuilder.addSection(buildTechnicalRiskSection_(analysis, message));
  cardBuilder.addSection(buildTechnicalMetaSection_(analysis, message));
  cardBuilder.addSection(buildBackSection_(message, "main"));

  return cardBuilder.build();
}

function buildTechnicalAuthSection_(message) {
  const section = CardService.newCardSection().setHeader("Identity & authentication");

  section.addWidget(infoButton_("ℹ️ What is SPF/DKIM/DMARC?", "authInfo", { returnTo: "technical", messageId: message.messageId || "" }));

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Auth (SPF / DKIM / DMARC)")
      .setContent(message.authentication.spf + " / " + message.authentication.dkim + " / " + message.authentication.dmarc)
  );

  if (message.fromDomain) section.addWidget(CardService.newKeyValue().setTopLabel("From domain").setContent(message.fromDomain));
  if (message.replyToDomain) section.addWidget(CardService.newKeyValue().setTopLabel("Reply-To domain").setContent(message.replyToDomain));
  if (message.returnPathDomain) section.addWidget(CardService.newKeyValue().setTopLabel("Return-Path domain").setContent(message.returnPathDomain));

  return section;
}

function buildTechnicalLinksSection_(analysis, message) {
  const section = CardService.newCardSection().setHeader("Link reputation");

  section.addWidget(infoButton_("ℹ️ What is link reputation?", "linkReputationInfo", { returnTo: "technical", messageId: message.messageId || "" }));

  const links = analysis && analysis.breakdown && analysis.breakdown.links ? analysis.breakdown.links : null;
  const rep = links && links.urlReputation ? links.urlReputation : null;

  if (!rep) {
    section.addWidget(CardService.newTextParagraph().setText("No link reputation data available."));
    return section;
  }

  const status = rep.status || "unknown";
  const checkedCount = typeof rep.checkedCount === "number" ? rep.checkedCount : 0;
  const maliciousCount = typeof rep.maliciousCount === "number" ? rep.maliciousCount : 0;
  const error = rep.error || "";

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Safe Browsing status")
      .setContent(String(status))
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Checked URLs")
      .setContent(String(checkedCount))
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Flagged as malicious")
      .setContent(String(maliciousCount))
  );

  if (error) {
    section.addWidget(
      CardService.newTextParagraph()
        .setText("Error: " + escapeHtml(String(error)))
    );
  }

  const sample = Array.isArray(rep.maliciousUrlsSample) ? rep.maliciousUrlsSample : [];
  if (sample.length) {
    const lines = sample.slice(0, 3).map((u, idx) => "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + escapeHtml(String(u))).join("<br>");
    section.addWidget(CardService.newTextParagraph().setText(lines));
  }

  return section;
}

function buildTechnicalConfidenceSection_(analysis, message) {
  const section = CardService.newCardSection().setHeader("Confidence");

  section.addWidget(infoButton_("ℹ️ What does confidence mean?", "confidenceInfo", { returnTo: "technical", messageId: message.messageId || "" }));

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Confidence (classification)")
      .setContent((analysis.confidence || "Low") + " • " + String(analysis.confidenceScore || 0) + "/100")
  );

  const rationale = Array.isArray(analysis.confidenceRationale) ? analysis.confidenceRationale : [];
  if (rationale.length) {
    const lines = rationale.slice(0, 4).map((x, idx) => "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + escapeHtml(String(x))).join("<br>");
    section.addWidget(CardService.newTextParagraph().setText(lines));
  } else {
    section.addWidget(CardService.newTextParagraph().setText("No confidence rationale provided."));
  }

  return section;
}

function buildTechnicalRiskSection_(analysis, message) {
  const section = CardService.newCardSection().setHeader("Risk metrics");

  section.addWidget(infoButton_("ℹ️ How scoring works", "scoringInfo", { returnTo: "technical", messageId: message.messageId || "" }));

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Safety score")
      .setContent(String(analysis.score || 0) + "/100")
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Final risk")
      .setContent(String(analysis.riskFinal || 0) + "/100")
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Hard checks risk")
      .setContent(String(analysis.riskHard || 0) + "/100")
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Free assessment risk")
      .setContent(String(analysis.riskFree || 0) + "/100")
  );

  const weights = analysis.riskWeights || {};
  const hardW = typeof weights.hard === "number" ? weights.hard : 0;
  const freeW = typeof weights.free === "number" ? weights.free : 0;

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel("Weights (hard / free)")
      .setContent(String(hardW) + " / " + String(freeW))
  );

  return section;
}

function buildTechnicalMetaSection_(analysis, message) {
  const section = CardService.newCardSection().setHeader("Meta");

  section.addWidget(infoButton_("ℹ️ Cache and settings storage", "storageInfo", { returnTo: "technical", messageId: message.messageId || "" }));

  const aiStatus = (analysis.aiStatus === "on") ? "On" : "Off";
  const aiMeta = "AI: " + aiStatus
  + (analysis.aiStatus === "on" && analysis.aiModel ? " • " + escapeHtml(String(analysis.aiModel)) : "")
  + (analysis.aiStatus === "on" && analysis.aiLatencyMs ? " • " + escapeHtml(String(analysis.aiLatencyMs)) + "ms" : "");

  section.addWidget(CardService.newTextParagraph().setText(aiMeta));

  if (analysis.aiStatus !== "on") {
    const reason = sanitizeAiReason_(analysis.aiReason) || "AI unavailable";
    section.addWidget(CardService.newTextParagraph().setText("Reason: " + escapeHtml(reason)));
  }

  if (analysis.version) section.addWidget(CardService.newKeyValue().setTopLabel("Engine version").setContent(analysis.version));
  if (analysis.traceId) section.addWidget(CardService.newTextParagraph().setText("Trace: " + escapeHtml(analysis.traceId)));

  return section;
}

function buildBackSection_(message, returnTo) {
  const section = CardService.newCardSection();

  section.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("navigateBack")
          .setParameters({ returnTo: String(returnTo || "home"), messageId: message && message.messageId ? String(message.messageId) : "" })
      )
  );

  return section;
}

/* =====================================================================
 * Info cards
 * ===================================================================== */

function infoButton_(label, infoKey, ctx) {
  const params = {
    infoKey: String(infoKey || ""),
    returnTo: String((ctx && ctx.returnTo) || "home"),
    messageId: String((ctx && ctx.messageId) || "")
  };

  return CardService.newTextButton()
    .setText(label)
    .setOnClickAction(
      CardService.newAction()
        .setFunctionName("openInfo")
        .setParameters(params)
    );
}

function openInfo(event) {
  const ctx = getNavContext_(event);
  const infoKey = ctx.infoKey || "helpMain";
  return buildInfoCard({ infoKey: infoKey, returnTo: ctx.returnTo, messageId: ctx.messageId });
}

function buildInfoCard(params) {
  const infoKey = params && params.infoKey ? String(params.infoKey) : "helpMain";
  const returnTo = params && params.returnTo ? String(params.returnTo) : "home";
  const messageId = params && params.messageId ? String(params.messageId) : "";

  const userSettings = getUserSettings();
  const lang = userSettings.language || "en";

  const content = infoContent_(infoKey, lang);

  const cardBuilder = CardService.newCardBuilder();
  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle(content.title)
      .setSubtitle(content.subtitle)
  );

  const section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(escapeHtml(content.body).replace(/\n/g, "<br>")));

  const actions = CardService.newCardSection();
  actions.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("navigateBack")
          .setParameters({ returnTo: returnTo, messageId: messageId })
      )
  );

  cardBuilder.addSection(section);
  cardBuilder.addSection(actions);
  return cardBuilder.build();
}

function infoContent_(key, lang) {
  const isHe = lang === "he";

  const map = {
    helpMain: isHe ? {
      title: "ScamurAI — Help",
      subtitle: "Glossary and controls",
      body: "Open an email to see analysis.\nSettings and History are on the homepage.\nUse ℹ️ buttons in Technical details for explanations."
    } : {
      title: "ScamurAI — Help",
      subtitle: "Glossary and controls",
      body: "Open an email to see analysis.\nSettings and History are on the homepage.\nUse ℹ️ buttons in Technical details for explanations."
    },
    authInfo: isHe ? {
      title: "SPF / DKIM / DMARC",
      subtitle: "Sender authentication",
      body: "SPF: checks if the sending server is allowed for the domain.\nDKIM: cryptographic signature proving the email was not altered.\nDMARC: policy that combines SPF/DKIM and guides how to handle failures."
    } : {
      title: "SPF / DKIM / DMARC",
      subtitle: "Sender authentication",
      body: "SPF: checks if the sending server is allowed for the domain.\nDKIM: cryptographic signature proving the email was not altered.\nDMARC: policy that combines SPF/DKIM and guides how to handle failures."
    },
    confidenceInfo: isHe ? {
      title: "Confidence",
      subtitle: "Classification stability",
      body: "Confidence measures stability of the verdict (Safe/Suspicious/Malicious), not the exact number.\nLow when evidence is weak, contradictory, ambiguous, or test-like."
    } : {
      title: "Confidence",
      subtitle: "Classification stability",
      body: "Confidence measures stability of the verdict (Safe/Suspicious/Malicious), not the exact number.\nLow when evidence is weak, contradictory, ambiguous, or test-like."
    },
    scoringInfo: isHe ? {
      title: "Scoring",
      subtitle: "How the score is computed",
      body: "When AI is available: it scores both hard checks and free assessment.\nWhen AI is unavailable: only deterministic hard checks are used.\nNavigation never triggers re-analysis; only Refresh does."
    } : {
      title: "Scoring",
      subtitle: "How the score is computed",
      body: "When AI is available: it scores both hard checks and free assessment.\nWhen AI is unavailable: only deterministic hard checks are used.\nNavigation never triggers re-analysis; only Refresh does."
    },
    storageInfo: isHe ? {
      title: "Cache & Settings",
      subtitle: "Where data is stored",
      body: "Analysis snapshot: stored per messageId in User Properties (stable navigation).\nCache: stored in Add-on User Cache with TTL.\nSettings/History: stored in User Properties per Google account."
    } : {
      title: "Cache & Settings",
      subtitle: "Where data is stored",
      body: "Analysis snapshot: stored per messageId in User Properties (stable navigation).\nCache: stored in Add-on User Cache with TTL.\nSettings/History: stored in User Properties per Google account."
    },
    linkReputationInfo: isHe ? {
      title: "Link reputation",
      subtitle: "Google Safe Browsing check",
      body: "The backend can query Google Safe Browsing for URL threat matches.\nStatus shows whether the check ran and how many URLs were scanned.\nIf flagged URLs exist, they are shown as a sample."
    } : {
      title: "Link reputation",
      subtitle: "Google Safe Browsing check",
      body: "The backend can query Google Safe Browsing for URL threat matches.\nStatus shows whether the check ran and how many URLs were scanned.\nIf flagged URLs exist, they are shown as a sample."
    }
  };

  return map[key] || map.helpMain;
}

/* =====================================================================
 * Settings UI
 * ===================================================================== */

function openSettings(event) {
  const ctx = getNavContext_(event);
  return buildSettingsCard(ctx);
}

function buildSettingsCard(ctx) {
  const settings = getUserSettings();
  const nav = ctx || { returnTo: "home", messageId: "" };

  const cardBuilder = CardService.newCardBuilder();
  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI — Settings")
      .setSubtitle("Preferences are stored per Google account")
  );

  const section = CardService.newCardSection().setHeader("Preferences");

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.CHECK_BOX)
      .setTitle("AI analysis")
      .setFieldName("aiEnabled")
      .addItem("Enabled", "true", !!settings.aiEnabled)
  );

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.DROPDOWN)
      .setTitle("View mode")
      .setFieldName("viewMode")
      .addItem("Basic", "basic", settings.viewMode === "basic")
      .addItem("Advanced", "advanced", settings.viewMode === "advanced")
  );

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.DROPDOWN)
      .setTitle("Sensitivity")
      .setFieldName("sensitivity")
      .addItem("Lenient", "lenient", settings.sensitivity === "lenient")
      .addItem("Balanced", "balanced", settings.sensitivity === "balanced")
      .addItem("Strict", "strict", settings.sensitivity === "strict")
  );

  section.addWidget(
    CardService.newTextInput()
      .setTitle("Hard checks weight (0.00 - 1.00)")
      .setFieldName("hardChecksWeight")
      .setValue(String(settings.hardChecksWeight))
  );

  section.addWidget(
    CardService.newTextInput()
      .setTitle("Allowlisted domains (comma-separated)")
      .setFieldName("allowlistedDomains")
      .setValue((settings.allowlistedDomains || []).join(","))
  );

  section.addWidget(
    CardService.newTextInput()
      .setTitle("Blocklisted domains (comma-separated)")
      .setFieldName("blocklistedDomains")
      .setValue((settings.blocklistedDomains || []).join(","))
  );

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.CHECK_BOX)
      .setTitle("Treat unknown authentication as risk")
      .setFieldName("treatAuthUnknownAsRisk")
      .addItem("Enabled", "true", !!settings.treatAuthUnknownAsRisk)
  );

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.CHECK_BOX)
      .setTitle("Assume test email if it contains testing words")
      .setFieldName("assumeTestEmailIfContainsTestingWords")
      .addItem("Enabled", "true", !!settings.assumeTestEmailIfContainsTestingWords)
  );

  section.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.DROPDOWN)
      .setTitle("Language")
      .setFieldName("language")
      .addItem("English", "en", settings.language === "en")
      .addItem("Hebrew", "he", settings.language === "he")
  );

  const actions = CardService.newCardSection().setHeader("Actions");

  actions.addWidget(
    CardService.newTextButton()
      .setText("Save settings")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("saveSettings")
          .setParameters(buildNavParams_(nav))
      )
  );

  actions.addWidget(
    CardService.newTextButton()
      .setText("Reset to defaults")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("resetSettings")
          .setParameters(buildNavParams_(nav))
      )
  );

  actions.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("navigateBack")
          .setParameters(buildNavParams_(nav))
      )
  );

  cardBuilder.addSection(section);
  cardBuilder.addSection(actions);
  return cardBuilder.build();
}

function saveSettings(event) {
  const ctx = getNavContext_(event);
  const form = (event && event.commonEventObject && event.commonEventObject.formInputs) ? event.commonEventObject.formInputs : {};

  const current = getUserSettings();

  const aiEnabled = readFormBoolOrDefault(form, "aiEnabled", current.aiEnabled);
  const viewMode = readFormString(form, "viewMode", current.viewMode || "basic");
  const sensitivity = readFormString(form, "sensitivity", current.sensitivity || "balanced");
  const hardChecksWeightRaw = readFormString(form, "hardChecksWeight", String(current.hardChecksWeight || "0.30"));
  const allowlistedRaw = readFormString(form, "allowlistedDomains", (current.allowlistedDomains || []).join(","));
  const blocklistedRaw = readFormString(form, "blocklistedDomains", (current.blocklistedDomains || []).join(","));
  const treatAuthUnknownAsRisk = readFormBoolOrDefault(form, "treatAuthUnknownAsRisk", current.treatAuthUnknownAsRisk);
  const assumeTestEmailIfContainsTestingWords = readFormBoolOrDefault(form, "assumeTestEmailIfContainsTestingWords", current.assumeTestEmailIfContainsTestingWords);
  const language = readFormString(form, "language", current.language || "en");

  const settings = normalizeSettings({
    aiEnabled: aiEnabled,
    viewMode: viewMode,
    sensitivity: sensitivity,
    hardChecksWeight: hardChecksWeightRaw,
    allowlistedDomains: splitDomains(allowlistedRaw),
    blocklistedDomains: splitDomains(blocklistedRaw),
    treatAuthUnknownAsRisk: treatAuthUnknownAsRisk,
    assumeTestEmailIfContainsTestingWords: assumeTestEmailIfContainsTestingWords,
    language: language
  });

  storeUserSettings(settings);
  return buildSettingsSavedCard_(settings, ctx);
}

function readFormBoolOrDefault(formInputs, fieldName, defaultValue) {
  const field = formInputs[fieldName];
  if (!field) return !!defaultValue;
  const values = field.stringInputs && field.stringInputs.value ? field.stringInputs.value : [];
  return values.indexOf("true") >= 0;
}

function buildSettingsSavedCard_(settings, ctx) {
  const nav = ctx || { returnTo: "home", messageId: "" };

  const cardBuilder = CardService.newCardBuilder();
  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI — Settings saved")
      .setSubtitle("Your preferences will apply to future analyses (after Refresh)")
  );

  const section = CardService.newCardSection().setHeader("Current settings");
  section.addWidget(CardService.newKeyValue().setTopLabel("AI").setContent(settings.aiEnabled ? "Enabled" : "Disabled"));
  section.addWidget(CardService.newKeyValue().setTopLabel("View mode").setContent(settings.viewMode));
  section.addWidget(CardService.newKeyValue().setTopLabel("Sensitivity").setContent(settings.sensitivity));
  section.addWidget(CardService.newKeyValue().setTopLabel("Hard checks weight").setContent(String(settings.hardChecksWeight)));
  section.addWidget(CardService.newKeyValue().setTopLabel("Allowlist").setContent((settings.allowlistedDomains || []).join(", ") || "(none)"));
  section.addWidget(CardService.newKeyValue().setTopLabel("Blocklist").setContent((settings.blocklistedDomains || []).join(", ") || "(none)"));
  section.addWidget(CardService.newKeyValue().setTopLabel("Auth unknown as risk").setContent(settings.treatAuthUnknownAsRisk ? "Enabled" : "Disabled"));
  section.addWidget(CardService.newKeyValue().setTopLabel("Test-email heuristic").setContent(settings.assumeTestEmailIfContainsTestingWords ? "Enabled" : "Disabled"));
  section.addWidget(CardService.newKeyValue().setTopLabel("Language").setContent(settings.language));

  const actions = CardService.newCardSection();

  actions.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("navigateBack")
          .setParameters(buildNavParams_(nav))
      )
  );

  cardBuilder.addSection(section);
  cardBuilder.addSection(actions);
  return cardBuilder.build();
}

function resetSettings(event) {
  const ctx = getNavContext_(event);
  const defaults = defaultUserSettings();
  storeUserSettings(defaults);
  return buildSettingsSavedCard_(defaults, ctx);
}

function addDomainToAllowlist(event) {
  const messageId = getEventParameter(event, "messageId");
  if (!messageId) return buildHomepageCard();

  const message = loadMessageById(messageId);
  const domain = normalizeDomain_(message.fromDomain);

  if (!domain) return buildHomepageCard();

  const settings = getUserSettings();
  if (!settings.allowlistedDomains.includes(domain)) {
    settings.allowlistedDomains.push(domain);
  }

  storeUserSettings(settings);

  return buildSimpleInfoCard_("Domain added to allowlist. Click 'Clear cache + re-run' to re-analyze.", messageId);
}

function addDomainToBlocklist(event) {
  const messageId = getEventParameter(event, "messageId");
  if (!messageId) return buildHomepageCard();

  const message = loadMessageById(messageId);
  const domain = normalizeDomain_(message.fromDomain);

  if (!domain) return buildHomepageCard();

  const settings = getUserSettings();
  if (!settings.blocklistedDomains.includes(domain)) {
    settings.blocklistedDomains.push(domain);
  }

  storeUserSettings(settings);

  return buildSimpleInfoCard_("Domain added to ScamurAI blocklist. Click 'Clear cache + re-run' to re-analyze.", messageId);
}

/* =====================================================================
 * History UI (display-only)
 * ===================================================================== */

function openHistory(event) {
  const ctx = getNavContext_(event);
  return buildHistoryCard(ctx);
}

function buildHistoryCard(ctx) {
  const items = getHistoryItems();
  const nav = ctx || { returnTo: "home", messageId: "" };

  const cardBuilder = CardService.newCardBuilder();
  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI — History")
      .setSubtitle("Display-only; does not affect scoring")
  );

  const section = CardService.newCardSection().setHeader("Recent analyses");

  if (!items.length) {
    section.addWidget(CardService.newTextParagraph().setText("No history yet."));
  } else {
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const line = escapeHtml(it.when) + " • " + escapeHtml(it.verdict) + " • " + escapeHtml(String(it.score)) + "/100"
        + (it.fromDomain ? " • " + escapeHtml(it.fromDomain) : "")
        + (it.aiAvailable ? "" : " • AI off");
      section.addWidget(CardService.newTextParagraph().setText(line));
    }
  }

  const actions = CardService.newCardSection().setHeader("Actions");
  actions.addWidget(
    CardService.newTextButton()
      .setText("Clear history")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("clearHistory")
          .setParameters(buildNavParams_(nav))
      )
  );
  actions.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("navigateBack")
          .setParameters(buildNavParams_(nav))
      )
  );

  cardBuilder.addSection(section);
  cardBuilder.addSection(actions);
  return cardBuilder.build();
}

function clearHistory(event) {
  const ctx = getNavContext_(event);
  storeHistoryItems([]);
  return buildHistoryCard(ctx);
}

function addHistoryItem(message, analysis) {
  const items = getHistoryItems();

  const when = new Date();
  const ts = when.toISOString().replace("T", " ").slice(0, 19);

  items.unshift({
    when: ts,
    subject: String(message.subject || "").slice(0, 80),
    fromDomain: String(message.fromDomain || ""),
    verdict: String(analysis.verdict || ""),
    score: typeof analysis.score === "number" ? analysis.score : 0,
    aiAvailable: !!analysis.aiAvailable
  });

  while (items.length > maxHistoryItems) items.pop();
  storeHistoryItems(items);
}

function buildSimpleInfoCard_(text, messageId) {
  const cardBuilder = CardService.newCardBuilder();

  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI")
  );

  const section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText(escapeHtml(text))
  );

  section.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("showMainView")
          .setParameters({ messageId: messageId })
      )
  );

  cardBuilder.addSection(section);
  return cardBuilder.build();
}

function buildWhyVerdictCard_(message, analysis) {
  const cardBuilder = CardService.newCardBuilder();

  const subtitle =
    String(analysis.verdict || "Unknown") + " • " + String(analysis.score || 0) + "/100"
    + (analysis.confidence ? " • " + String(analysis.confidence) : "")
    + (analysis.cached ? " • Cached" : "");

  cardBuilder.setHeader(
    CardService.newCardHeader()
      .setTitle("ScamurAI — Why this verdict?")
      .setSubtitle(subtitle)
  );

  const section = CardService.newCardSection().setHeader("Top reasons");

  // Prefer signals if present (advanced-like), else fallback to keyFindings/rationale
  const signals = Array.isArray(analysis && analysis.signals) ? analysis.signals : [];
  if (signals.length) {
    const top = signals.slice().sort((a, b) => (b.points || 0) - (a.points || 0)).slice(0, 5);
    const lines = top.map((s, idx) => {
      const title = escapeHtml(String(s.title || "Signal"));
      const pts = escapeHtml(String(s.points || 0));
      const ev = s.evidence ? " — " + escapeHtml(String(s.evidence)) : "";
      return "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + title + " (" + pts + ")" + ev;
    }).join("<br>");
    section.addWidget(CardService.newTextParagraph().setText(lines));
  } else {
    const reasons = pickTopReasons_(analysis, 5);
    if (reasons.length) {
      const lines = reasons.map((x, idx) =>
        "<b>" + escapeHtml(String(idx + 1) + ".") + "</b> " + escapeHtml(String(x))
      ).join("<br>");
      section.addWidget(CardService.newTextParagraph().setText(lines));
    } else {
      section.addWidget(CardService.newTextParagraph().setText("No reasons available."));
    }
  }

  const actions = CardService.newCardSection();
  actions.addWidget(
    CardService.newTextButton()
      .setText("Back")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("showMainView")
          .setParameters({ messageId: message && message.messageId ? String(message.messageId) : "" })
      )
  );

  cardBuilder.addSection(section);
  cardBuilder.addSection(actions);
  return cardBuilder.build();
}

/* =====================================================================
 * Storage: cache + settings + history
 * ===================================================================== */

function buildCacheKey(messageId) {
  return "analysis:" + String(messageId);
}

function removeCachedAnalysis(messageId) {
  CacheService.getUserCache().remove(buildCacheKey(messageId));
}

function defaultUserSettings() {
  return {
    aiEnabled: true,
    viewMode: "basic",
    sensitivity: "balanced",
    hardChecksWeight: 0.30,
    allowlistedDomains: [],
    blocklistedDomains: [],
    treatAuthUnknownAsRisk: true,
    assumeTestEmailIfContainsTestingWords: true,
    language: "en"
  };
}

function getUserSettings() {
  const props = PropertiesService.getUserProperties();
  const raw = props.getProperty(userSettingsKey);
  if (!raw) return defaultUserSettings();

  try {
    const parsed = JSON.parse(raw);
    return normalizeSettings(parsed);
  } catch (e) {
    return defaultUserSettings();
  }
}

function storeUserSettings(settings) {
  const props = PropertiesService.getUserProperties();
  props.setProperty(userSettingsKey, JSON.stringify(normalizeSettings(settings)));
}

function normalizeSettings(input) {
  const defaults = defaultUserSettings();
  const settings = input || {};

  const aiEnabled = settings.aiEnabled === false ? false : true;

  const viewMode = String(settings.viewMode || defaults.viewMode).toLowerCase();
  const finalViewMode = (["basic", "advanced"].indexOf(viewMode) >= 0) ? viewMode : defaults.viewMode;

  const sensitivity = String(settings.sensitivity || defaults.sensitivity).toLowerCase();
  const finalSensitivity = (["lenient", "balanced", "strict"].indexOf(sensitivity) >= 0) ? sensitivity : defaults.sensitivity;

  let hardW = parseFloat(settings.hardChecksWeight);
  if (isNaN(hardW)) hardW = defaults.hardChecksWeight;
  hardW = Math.max(0.0, Math.min(1.0, hardW));

  const allowlistedDomains = Array.isArray(settings.allowlistedDomains) ? settings.allowlistedDomains : defaults.allowlistedDomains;
  const blocklistedDomains = Array.isArray(settings.blocklistedDomains) ? settings.blocklistedDomains : defaults.blocklistedDomains;

  const language = String(settings.language || defaults.language).toLowerCase();
  const finalLanguage = (["en", "he"].indexOf(language) >= 0) ? language : defaults.language;

  return {
    aiEnabled: !!aiEnabled,
    viewMode: finalViewMode,
    sensitivity: finalSensitivity,
    hardChecksWeight: hardW,
    allowlistedDomains: normalizeDomainList_(allowlistedDomains),
    blocklistedDomains: normalizeDomainList_(blocklistedDomains),
    treatAuthUnknownAsRisk: !!settings.treatAuthUnknownAsRisk,
    assumeTestEmailIfContainsTestingWords: !!settings.assumeTestEmailIfContainsTestingWords,
    language: finalLanguage
  };
}

function normalizeDomainList_(arr) {
  const out = [];
  const seen = {};
  const list = Array.isArray(arr) ? arr : [];
  for (let i = 0; i < list.length; i++) {
    const d = normalizeDomain_(String(list[i] || ""));
    if (!d) continue;
    if (seen[d]) continue;
    seen[d] = true;
    out.push(d);
    if (out.length >= 50) break;
  }
  return out;
}

function splitDomains(text) {
  const raw = String(text || "");
  if (!raw.trim()) return [];
  return raw.split(",").map(x => normalizeDomain_(x)).filter(x => !!x);
}

function normalizeDomain_(value) {
  const v = String(value || "").trim().toLowerCase();
  return v.replace(/\s+/g, "");
}

function getHistoryItems() {
  const props = PropertiesService.getUserProperties();
  const raw = props.getProperty(historyKey);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function storeHistoryItems(items) {
  const props = PropertiesService.getUserProperties();
  props.setProperty(historyKey, JSON.stringify(Array.isArray(items) ? items : []));
}

/* =====================================================================
 * Gmail parsing utilities
 * ===================================================================== */

function readHeader(gmailMessage, headerName) {
  const headers = gmailMessage && gmailMessage.payload && gmailMessage.payload.headers ? gmailMessage.payload.headers : [];
  const target = String(headerName).toLowerCase();

  for (let i = 0; i < headers.length; i++) {
    const header = headers[i];
    if (header && header.name && String(header.name).toLowerCase() === target) return header.value || "";
  }
  return "";
}

function extractBodies(gmailMessage) {
  const payload = gmailMessage && gmailMessage.payload ? gmailMessage.payload : null;
  const result = { plainText: "", htmlText: "" };
  if (!payload) return result;

  walkMimeParts_(payload, part => {
    const mimeType = (part.mimeType || "").toLowerCase();
    const data = part.body && part.body.data ? part.body.data : "";
    if (!data) return;

    const decoded = decodeBase64Url_(data);

    if (mimeType === "text/plain" && !result.plainText) result.plainText = decoded;
    if (mimeType === "text/html" && !result.htmlText) result.htmlText = decoded;
  });

  if (!result.plainText && payload.body && payload.body.data && (payload.mimeType || "").toLowerCase() === "text/plain") {
    result.plainText = decodeBase64Url_(payload.body.data);
  }

  if (!result.htmlText && payload.body && payload.body.data && (payload.mimeType || "").toLowerCase() === "text/html") {
    result.htmlText = decodeBase64Url_(payload.body.data);
  }

  return result;
}

function walkMimeParts_(part, visitor) {
  visitor(part);
  const parts = part.parts || [];
  for (let i = 0; i < parts.length; i++) walkMimeParts_(parts[i], visitor);
}

function decodeBase64Url_(base64Url) {
  const base64 = String(base64Url).replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4 ? "=".repeat(4 - (base64.length % 4)) : "";
  return Utilities.newBlob(Utilities.base64Decode(base64 + padding)).getDataAsString("UTF-8");
}

function stripHtml(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<\/?[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/* =====================================================================
 * Identity utilities
 * ===================================================================== */

function extractDomain(headerValue) {
  const value = String(headerValue || "").trim();
  const match = value.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
  return match ? match[1].toLowerCase() : "";
}

function parseAuthenticationResults(value) {
  const text = String(value || "").toLowerCase();
  return {
    spf: extractAuthToken_(text, "spf"),
    dkim: extractAuthToken_(text, "dkim"),
    dmarc: extractAuthToken_(text, "dmarc")
  };
}

function extractAuthToken_(text, key) {
  const regex = new RegExp("\\b" + key + "=([a-z]+)\\b", "i");
  const match = String(text || "").match(regex);
  return match && match[1] ? String(match[1]).toLowerCase() : "unknown";
}

/* =====================================================================
 * Form utilities
 * ===================================================================== */

function readFormString(formInputs, fieldName, fallback) {
  const field = formInputs[fieldName];
  if (!field) return fallback;
  const value = field.stringInputs && field.stringInputs.value && field.stringInputs.value.length ? field.stringInputs.value[0] : "";
  return value ? String(value) : fallback;
}

function readFormBool(formInputs, fieldName) {
  const field = formInputs[fieldName];
  if (!field) return false;
  const values = field.stringInputs && field.stringInputs.value ? field.stringInputs.value : [];
  return values.indexOf("true") >= 0;
}

function getEventParameter(event, name) {
  return event && event.parameters && event.parameters[name] ? String(event.parameters[name]) : "";
}

/* =====================================================================
 * Presentation utilities
 * ===================================================================== */

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildAiStatusLine_(analysis) {
  const status = analysis.aiStatus ? String(analysis.aiStatus).toLowerCase() : (analysis.aiAvailable ? "on" : "off");
  const isOn = status === "on";

  const model = analysis.aiModelMeta ? String(analysis.aiModelMeta) : (analysis.aiModel ? String(analysis.aiModel) : "");
  const base = "AI: " + (isOn ? "On" : "Off");

  if (isOn) {
    return model ? "<b>" + base + "</b> • " + escapeHtml(model) : "<b>" + base + "</b>";
  }

  const reason = sanitizeAiReason_(analysis.aiReason);
  return reason
    ? "<b>" + base + "</b> — " + escapeHtml(reason)
    : "<b>" + base + "</b>";
}

function pickTopReasons_(analysis, maxItems) {
  const out = [];

  const keyFindings = Array.isArray(analysis && analysis.keyFindings) ? analysis.keyFindings : [];
  for (let i = 0; i < keyFindings.length && out.length < maxItems; i++) {
    const s = String(keyFindings[i] || "").trim();
    if (s) out.push(s);
  }

  if (out.length >= maxItems) return out;

  const rationale = Array.isArray(analysis && analysis.confidenceRationale) ? analysis.confidenceRationale : [];
  for (let j = 0; j < rationale.length && out.length < maxItems; j++) {
    const s = String(rationale[j] || "").trim();
    if (s) out.push(s);
  }

  return out;
}

function buildAiStatusCompactSection_(analysis) {
  const section = CardService.newCardSection();

  const status = analysis && analysis.aiStatus ? String(analysis.aiStatus).toLowerCase() : (analysis && analysis.aiAvailable ? "on" : "off");
  const isOn = status === "on";

  let line = "<b>AI:</b> " + (isOn ? "On" : "Off");

  if (isOn) {
    const model = analysis && (analysis.aiModelMeta || analysis.aiModel) ? String(analysis.aiModelMeta || analysis.aiModel) : "";
    if (model) line += " • " + escapeHtml(model);
  } else {
    const reason = sanitizeAiReason_(analysis && analysis.aiReason ? analysis.aiReason : "");
    if (reason) line += " — " + escapeHtml(reason);
  }

  section.addWidget(CardService.newTextParagraph().setText(line));
  return section;
}

function sanitizeAiReason_(reason) {
  const s = String(reason || "").trim();
  if (!s) return "";
  const lower = s.toLowerCase();

  if (lower.indexOf("resource_exhausted") >= 0 || lower.indexOf("quota exceeded") >= 0 || lower.indexOf("rate-limit") >= 0 || lower.indexOf("generate_content") >= 0) {
    return "Quota exceeded; retry later.";
  }

  if (lower.indexOf("http 429") >= 0 || lower.indexOf(" 429 ") >= 0) {
    return "Quota exceeded; retry later.";
  }

  if (lower.indexOf("permission_denied") >= 0 || lower.indexOf("unauthenticated") >= 0 || lower.indexOf("http 401") >= 0) {
    return "Authentication failed; check API key or permissions.";
  }

  if (lower.indexOf("unavailable") >= 0 || lower.indexOf("http 503") >= 0) {
    return "Service temporarily unavailable; retry later.";
  }

  if (lower.indexOf("{'error'") >= 0 || (s[0] === "{" && s[s.length - 1] === "}") || s.indexOf("details") >= 0) {
    const firstLine = s.split("\n")[0].trim();
    if (firstLine) return firstLine.length > 120 ? firstLine.slice(0, 117) + "..." : firstLine;
    return "AI unavailable; retry later.";
  }

  const oneLine = s.replace(/\s+/g, " ").trim();
  return oneLine.length > 120 ? oneLine.slice(0, 117) + "..." : oneLine;
}

function buildSafeBrowsingLine_(analysis) {
  const status = analysis.safeBrowsingStatus ? String(analysis.safeBrowsingStatus) : "";
  if (!status) return "";

  const checked = typeof analysis.safeBrowsingChecked === "number" ? analysis.safeBrowsingChecked : 0;
  const malicious = typeof analysis.safeBrowsingMalicious === "number" ? analysis.safeBrowsingMalicious : 0;

  return "<b>Safe Browsing:</b> " + escapeHtml(status) + " • checked=" + escapeHtml(String(checked)) + " • malicious=" + escapeHtml(String(malicious));
}

function makeBarHtml_(score, segments) {
  const s = typeof score === "number" ? score : parseFloat(score);
  const val = isNaN(s) ? 0 : Math.max(0, Math.min(100, s));
  const seg = Math.max(5, Math.min(20, segments || 10));
  const filled = Math.round((val / 100) * seg);

  const full = "█".repeat(filled);
  const empty = "░".repeat(seg - filled);

  const color = val >= 70 ? "#1b5e20" : (val >= 40 ? "#ef6c00" : "#b71c1c");
  return "<font color=\"" + color + "\">" + escapeHtml(full) + "</font>" + escapeHtml(empty);
}
