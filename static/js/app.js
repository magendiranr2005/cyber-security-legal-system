const state = {
  sessionId: getOrCreateSessionId(),
  lastFinalReport: null,
  currentComplaint: "",
  pendingQuestion: "",
  followUpAnswers: {},
};
let submissionInProgress = false;
let reportSaveInProgress = false;

const chatMessages = document.getElementById("chatMessages");
const chatForm = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");
const sendButton = document.getElementById("sendButton");
const questionArea = document.getElementById("questionArea");
const telemetryCategory = document.getElementById("telemetryCategory");
const telemetryConfidence = document.getElementById("telemetryConfidence");
const telemetryIndicators = document.getElementById("telemetryIndicators");
const categoryValue = document.getElementById("categoryValue");
const confidenceValue = document.getElementById("confidenceValue");
const confidenceLevel = document.getElementById("confidenceLevel");
const indicatorList = document.getElementById("indicatorList");
const assessmentContent = document.getElementById("assessmentContent");
const legalGuidance = document.getElementById("legalGuidance");
const evidenceGuide = document.getElementById("evidenceGuide");
const reportList = document.getElementById("reportList");
const saveReportButton = document.getElementById("saveReportButton");
const newComplaintButton = document.getElementById("newComplaintButton");
const viewReportButton = document.getElementById("viewReportButton");
const downloadReportButton = document.getElementById("downloadReportButton");
const printReportButton = document.getElementById("printReportButton");
const charCount = document.getElementById("charCount");
const chatStatus = document.getElementById("chatStatus");

function createSessionId() {
  const randomValue = typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID()
    : `session-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  localStorage.setItem("cyberlegal_session_id", randomValue);
  return randomValue;
}

function getOrCreateSessionId() {
  const requestedSessionId = new URLSearchParams(window.location.search).get("session_id");
  if (typeof requestedSessionId === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(requestedSessionId)) {
    localStorage.setItem("cyberlegal_session_id", requestedSessionId);
    return requestedSessionId;
  }
  return createSessionId();
}

function updateActiveSessionUrl(sessionId) {
  if (!sessionId) return;
  const url = new URL(window.location.href);
  url.searchParams.set("session_id", sessionId);
  window.history.replaceState(null, "", url);
}

function clearActiveSessionUrl() {
  const url = new URL(window.location.href);
  url.searchParams.delete("session_id");
  window.history.replaceState(null, "", url);
}

function addMessage(role, text, isError = false, retrySessionId = null) {
  if (!chatMessages) return;
  const wrapper = document.createElement("div");
  wrapper.className = `message ${role}`;
  if (isError) wrapper.classList.add("error");
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text;
  wrapper.appendChild(bubble);
  if (retrySessionId) {
    const retryButton = document.createElement("button");
    retryButton.className = "action-button secondary retry-analysis-button";
    retryButton.type = "button";
    retryButton.textContent = "Retry analysis";
    retryButton.addEventListener("click", () => retryChatAnalysis(retrySessionId));
    wrapper.appendChild(retryButton);
  }
  chatMessages.appendChild(wrapper);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function addSavedReportNotice(report) {
  if (!chatMessages || !report?.id) return;
  const wrapper = document.createElement("div");
  wrapper.className = "message assistant";
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  const label = document.createElement("p");
  label.textContent = `Saved report ${report.report_ref || report.id} · ${report.created_at || "Saved"}`;
  const link = document.createElement("a");
  link.href = `/report/${encodeURIComponent(report.id)}`;
  link.textContent = "View report";
  bubble.append(label, link);
  wrapper.appendChild(bubble);
  chatMessages.appendChild(wrapper);
}

function updateCharCount() {
  if (!charCount || !chatInput) return;
  charCount.textContent = `${chatInput.value.length} / 2500`;
}

function bindNavigation() {
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((link) => link.classList.remove('active'));
      item.classList.add('active');
    });
  });
}

function setLoadingState(isLoading) {
  if (sendButton) {
    sendButton.disabled = isLoading;
    sendButton.textContent = isLoading ? "Analyzing incident..." : "Analyze incident";
  }
  if (chatInput) chatInput.disabled = isLoading;
  if (chatStatus) chatStatus.textContent = isLoading ? "Analyzing your saved complaint..." : "";
  if (newComplaintButton) newComplaintButton.disabled = isLoading;
  document.querySelectorAll(".retry-analysis-button, .option-button").forEach((button) => {
    button.disabled = isLoading;
  });
}

function renderQuestion(question, options) {
  if (!questionArea) return;
  questionArea.replaceChildren();
  const box = document.createElement("div");
  box.className = "question-box";
  const heading = document.createElement("h4");
  heading.textContent = question;
  box.appendChild(heading);
  const optionList = document.createElement("div");
  optionList.className = "option-list";
  options.forEach((option) => {
    const button = document.createElement("button");
    button.className = "option-button";
    button.type = "button";
    button.textContent = option;
    optionList.appendChild(button);
  });
  box.appendChild(optionList);
  questionArea.appendChild(box);

  questionArea.querySelectorAll(".option-button").forEach((button) => {
    button.addEventListener("click", () => {
      const text = button.textContent.trim();
      addMessage("user", text);
      questionArea.innerHTML = "";
      submitChatMessage(text);
    });
  });
}

function renderIndicators(items) {
  if (!indicatorList) return;
  indicatorList.innerHTML = "";
  if (!items || items.length === 0) {
    indicatorList.innerHTML = "<li>No indicators yet</li>";
    return;
  }

  items.slice(0, 6).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    indicatorList.appendChild(li);
  });
}

function updateTelemetry(category, confidence, indicators, language, confidenceLabel) {
  if (telemetryCategory) telemetryCategory.textContent = category || "Awaiting analysis";
  if (telemetryConfidence) telemetryConfidence.textContent = `${confidence || 0}%`;
  if (telemetryIndicators) telemetryIndicators.textContent = indicators && indicators.length ? indicators.length : 0;
  if (categoryValue) categoryValue.textContent = category || "--";
  if (confidenceValue) confidenceValue.textContent = confidence !== undefined ? `${confidence}%` : "--";
  if (confidenceLevel) confidenceLevel.textContent = confidenceLabel || (confidence <= 39 ? "Low Confidence" : confidence <= 69 ? "Medium Confidence" : "High Confidence");
  const languageValue = document.getElementById("languageValue");
  if (languageValue) languageValue.textContent = language || "Auto";
  renderIndicators(indicators || []);
}

function renderLegalGuidance(legalGuidanceData) {
  if (!legalGuidance) return;
  if (!legalGuidanceData || Object.keys(legalGuidanceData).length === 0) {
    legalGuidance.textContent = "No legal guidance generated yet.";
    return;
  }
  legalGuidance.replaceChildren();
  const container = document.createElement("div");
  const addParagraph = (label, value) => {
    const paragraph = document.createElement("p");
    if (label) {
      const strong = document.createElement("strong");
      strong.textContent = label;
      paragraph.appendChild(strong);
      paragraph.appendChild(document.createTextNode(" "));
    }
    paragraph.appendChild(document.createTextNode(value || "Not available."));
    container.appendChild(paragraph);
  };
  addParagraph("", legalGuidanceData.category || "Legal guidance");
  addParagraph("", legalGuidanceData.general_legal_explanation || "No summary available.");
  addParagraph("Relevant law guidance:", legalGuidanceData.relevant_indian_law || "Preliminary guidance only.");
  if (legalGuidanceData.verification_note) {
    addParagraph("Legal verification:", legalGuidanceData.verification_note);
  }
  if (Array.isArray(legalGuidanceData.topics_for_review) && legalGuidanceData.topics_for_review.length) {
    const topicsHeading = document.createElement("p");
    const topicsLabel = document.createElement("strong");
    topicsLabel.textContent = "Potential topics for review:";
    topicsHeading.appendChild(topicsLabel);
    container.appendChild(topicsHeading);
    const topics = document.createElement("ul");
    legalGuidanceData.topics_for_review.forEach((topic) => {
      const entry = document.createElement("li");
      entry.textContent = topic;
      topics.appendChild(entry);
    });
    container.appendChild(topics);
  }
  const applicableLaws = legalGuidanceData.applicable_laws || legalGuidanceData.legal_provisions || [];
  if (applicableLaws.length) {
    const heading = document.createElement("p");
    const strong = document.createElement("strong");
    strong.textContent = "Possible applicable law:";
    heading.appendChild(strong);
    container.appendChild(heading);
    const laws = document.createElement("ul");
    applicableLaws.forEach((item) => {
      const entry = document.createElement("li");
      entry.textContent = `${item.act || "Applicable law"} — Section ${item.section || "N/A"} — ${item.title || "Cybercrime provision"}`;
      laws.appendChild(entry);
    });
    container.appendChild(laws);
  }
  const consequencesHeading = document.createElement("p");
  consequencesHeading.textContent = "Potential consequences:";
  container.appendChild(consequencesHeading);
  const consequences = document.createElement("ul");
  (legalGuidanceData.potential_consequences || []).forEach((item) => {
    const entry = document.createElement("li");
    entry.textContent = item;
    consequences.appendChild(entry);
  });
  if (!consequences.childElementCount) {
    const entry = document.createElement("li");
    entry.textContent = "Not specified.";
    consequences.appendChild(entry);
  }
  container.appendChild(consequences);
  addParagraph("Disclaimer:", legalGuidanceData.disclaimer || "This information is preliminary educational guidance and is not a substitute for advice from a qualified legal professional.");
  legalGuidance.appendChild(container);
}

function renderEvidence(items) {
  if (!evidenceGuide) return;
  evidenceGuide.innerHTML = "";
  if (!items || items.length === 0) {
    evidenceGuide.innerHTML = "<li>No evidence guidance available.</li>";
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    evidenceGuide.appendChild(li);
  });
}

function renderAssessment(data) {
  if (!assessmentContent) return;
  if (!data) {
    assessmentContent.textContent = "Awaiting an assessment.";
    return;
  }

  const legalSummary = data.legal_guidance && data.legal_guidance.general_legal_explanation
    ? data.legal_guidance.general_legal_explanation
    : "No detailed legal explanation is currently available.";

  assessmentContent.replaceChildren();
  const container = document.createElement("div");
  const values = [
    ["Likely crime type:", data.crime_type || data.category || "Uncertain"],
    ["Related category:", data.related_category || "Not specified"],
    ["Confidence (AI estimate):", `${data.confidence ?? 0}%`],
    ["Severity:", data.severity || data.urgency || "Uncertain"],
    ["Severity explanation:", data.severity_explanation || "No severity explanation was provided."],
    ["Summary:", data.summary || data.response || "Assessment complete."],
    ["Overview:", legalSummary],
  ];
  values.forEach(([label, value]) => {
    const paragraph = document.createElement("p");
    const strong = document.createElement("strong");
    strong.textContent = label;
    paragraph.appendChild(strong);
    paragraph.appendChild(document.createTextNode(` ${value}`));
    container.appendChild(paragraph);
  });
  const heading = document.createElement("p");
  heading.textContent = "Recommended next steps:";
  container.appendChild(heading);
  const steps = document.createElement("ul");
  (data.recommended_actions || data.next_steps || []).forEach((step) => {
    const item = document.createElement("li");
    item.textContent = step;
    steps.appendChild(item);
  });
  if (!steps.childElementCount) {
    const item = document.createElement("li");
    item.textContent = "No next steps available.";
    steps.appendChild(item);
  }
  container.appendChild(steps);
  const evidenceItems = data.evidence_to_preserve || data.evidence || [];
  if (evidenceItems.length) {
    const evidenceHeading = document.createElement("p");
    evidenceHeading.textContent = "Evidence to preserve:";
    container.appendChild(evidenceHeading);
    const evidenceList = document.createElement("ul");
    evidenceItems.forEach((evidence) => {
      const item = document.createElement("li");
      item.textContent = evidence;
      evidenceList.appendChild(item);
    });
    container.appendChild(evidenceList);
  }
  const reportedFacts = data.facts || [];
  if (reportedFacts.length) {
    const factsHeading = document.createElement("p");
    factsHeading.textContent = "Reported facts:";
    container.appendChild(factsHeading);
    const factsList = document.createElement("ul");
    reportedFacts.forEach((fact) => {
      const item = document.createElement("li");
      item.textContent = fact;
      factsList.appendChild(item);
    });
    container.appendChild(factsList);
  }
  const missingInformation = data.missing_information || [];
  if (missingInformation.length) {
    const missingHeading = document.createElement("p");
    missingHeading.textContent = "Information still needed:";
    container.appendChild(missingHeading);
    const missingList = document.createElement("ul");
    missingInformation.forEach((fact) => {
      const item = document.createElement("li");
      item.textContent = fact;
      missingList.appendChild(item);
    });
    container.appendChild(missingList);
  }
  if (data.disclaimer) {
    const disclaimer = document.createElement("p");
    const label = document.createElement("strong");
    label.textContent = "Disclaimer:";
    disclaimer.append(label, document.createTextNode(` ${data.disclaimer}`));
    container.appendChild(disclaimer);
  }
  assessmentContent.appendChild(container);
}

function renderReports(reports) {
  if (!reportList) return;
  if (!reports || reports.length === 0) {
    reportList.textContent = "No saved reports yet.";
    return;
  }

  reportList.replaceChildren();
  reports.slice(0, 6).forEach((report) => {
    const item = document.createElement("div");
    item.className = "report-item";
    const category = document.createElement("strong");
    category.textContent = report.detected_category || "Uncertain";
    const confidence = document.createElement("span");
    confidence.textContent = `Confidence: ${report.confidence || 0}%`;
    const createdAt = document.createElement("small");
    createdAt.textContent = report.created_at || "Recent report";
    item.append(category, document.createElement("br"), confidence, document.createElement("br"), createdAt);
    reportList.appendChild(item);
  });
}

async function loadReports() {
  if (!reportList) return;
  try {
    const response = await fetch("/reports");
    if (!response.ok) {
      throw new Error("Could not load reports.");
    }
    const data = await response.json();
    renderReports(data.reports || []);
  } catch (error) {
    reportList.textContent = "Reports could not be loaded right now.";
  }
}

async function loadExistingChat() {
  const requestedSessionId = new URLSearchParams(window.location.search).get("session_id");
  if (!requestedSessionId || !chatMessages) return;

  try {
    const response = await fetch(`/api/chat-history/${encodeURIComponent(requestedSessionId)}`);
    if (!response.ok) throw new Error("Chat session could not be loaded.");
    const data = await response.json();
    if (!data.session_id) throw new Error("Chat session not found.");

    state.sessionId = data.session_id;
    state.currentComplaint = data.complaint || "";
    localStorage.setItem("cyberlegal_session_id", data.session_id);
    chatMessages.replaceChildren();
    (data.messages || []).forEach((item) => addMessage(item.role === "user" ? "user" : "assistant", item.message));
    (data.related_reports || []).forEach(addSavedReportNotice);
    if (data.status === "Analysis unavailable") {
      addMessage(
        "assistant",
        "The saved complaint has not been assessed yet. You can retry its analysis.",
        true,
        data.session_id
      );
    }
    const analysis = data.analysis || {};
    if (analysis.type === "final") {
      state.lastFinalReport = analysis;
      const latestReport = (data.related_reports || [])[0];
      if (latestReport) {
        state.lastFinalReport.savedReportId = latestReport.id;
        if (saveReportButton) saveReportButton.disabled = true;
        if (viewReportButton) viewReportButton.disabled = false;
        if (downloadReportButton) downloadReportButton.disabled = false;
        if (printReportButton) printReportButton.disabled = false;
      }
      renderAssessment(analysis);
      renderLegalGuidance(analysis.legal_guidance || {});
      renderEvidence(analysis.evidence_to_preserve || analysis.evidence || []);
    } else if (analysis.type === "follow_up" || analysis.type === "question") {
      state.pendingQuestion = analysis.question || analysis.follow_up_question || "";
      if (state.pendingQuestion) renderQuestion(state.pendingQuestion, analysis.options || []);
    }
    updateTelemetry(
      data.detected_category || "Uncertain",
      data.confidence || 0,
      analysis.indicators || [],
      data.detected_language || "English",
      analysis.confidence_label
    );
  } catch (error) {
    state.sessionId = createSessionId();
    clearActiveSessionUrl();
    state.currentComplaint = "";
    addMessage("assistant", "This saved chat could not be loaded. You can start a new assessment here.");
  }
}

async function submitChatMessage(messageText) {
  if (submissionInProgress) return;
  const trimmedMessage = messageText.trim();
  if (!trimmedMessage) {
    addMessage("assistant", "Please enter a complaint before sending.");
    return;
  }

  if (!state.currentComplaint) {
    state.currentComplaint = trimmedMessage;
  }
  const answerToQuestion = state.pendingQuestion;

  submissionInProgress = true;
  setLoadingState(true);

  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: trimmedMessage,
        session_id: state.sessionId.trim() || null,
      }),
    });

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an unreadable response. Your text is still available; please try again.");
    }

    if (!response.ok) {
      if (data?.session_id) {
        state.sessionId = data.session_id;
        localStorage.setItem("cyberlegal_session_id", state.sessionId);
        updateActiveSessionUrl(state.sessionId);
      }
      if (data?.complaint) state.currentComplaint = data.complaint;
      addMessage(
        "assistant",
        data?.response || data?.error || "I couldn't process that message right now. Please try again.",
        true,
        data?.retry_available ? (data.session_id || state.sessionId) : null
      );
      return;
    }
    if (!["follow_up", "question", "final"].includes(data?.type)) {
      addMessage(
        "assistant",
        "The server response did not contain a completed analysis. Your text is still available; please retry.",
        true
      );
      return;
    }

    state.sessionId = data.session_id || state.sessionId;
    if (state.sessionId) {
      localStorage.setItem("cyberlegal_session_id", state.sessionId);
      updateActiveSessionUrl(state.sessionId);
    }
    state.currentComplaint = data.complaint || state.currentComplaint;
    if (chatInput && chatInput.value.trim() === trimmedMessage) {
      chatInput.value = "";
      updateCharCount();
    }

    if (data.type === "follow_up" || data.type === "question") {
      if (answerToQuestion) state.followUpAnswers[answerToQuestion] = trimmedMessage;
      state.pendingQuestion = data.question || data.response || "";
      addMessage("assistant", data.response || "I need a little more information.");
      renderQuestion(data.question || data.response || "Can you clarify this?", data.options || []);
      updateTelemetry(data.category || "Uncertain", data.confidence || 0, data.indicators || [], data.language, data.confidence_label);
    } else if (data.type === "final") {
      if (answerToQuestion) state.followUpAnswers[answerToQuestion] = trimmedMessage;
      state.pendingQuestion = "";
      state.lastFinalReport = data;
      addMessage("assistant", data.response || "Assessment complete.");
      renderAssessment(data);
      renderLegalGuidance(data.legal_guidance || {});
      renderEvidence(data.evidence_to_preserve || data.evidence || []);
      updateTelemetry(data.category || "Uncertain", data.confidence || 0, data.indicators || [], data.language, data.confidence_label);
    }
  } catch (error) {
    addMessage(
      "assistant",
      error.message || "The AI service is unavailable. Your complaint was not assessed; please try again later.",
      true,
      null
    );
  } finally {
    submissionInProgress = false;
    setLoadingState(false);
  }
}

async function retryChatAnalysis(sessionId) {
  if (submissionInProgress || !sessionId) return;

  const answerToQuestion = state.pendingQuestion;
  const retriedMessage = chatInput ? chatInput.value.trim() : "";
  submissionInProgress = true;
  setLoadingState(true);

  try {
    const response = await fetch("/api/chat/retry", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({session_id: sessionId}),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an unreadable response. Your saved complaint is still available.");
    }

    if (!response.ok) {
      addMessage(
        "assistant",
        data?.response || data?.error || "Analysis could not be retried. Your complaint remains saved.",
        true,
        data?.retry_available ? (data.session_id || sessionId) : null
      );
      return;
    }
    if (!["follow_up", "question", "final"].includes(data?.type)) {
      addMessage(
        "assistant",
        "The server response did not contain a completed analysis. Your saved complaint is still available; please retry.",
        true,
        sessionId
      );
      return;
    }

    state.sessionId = data.session_id || sessionId;
    localStorage.setItem("cyberlegal_session_id", state.sessionId);
    updateActiveSessionUrl(state.sessionId);
    state.currentComplaint = data.complaint || state.currentComplaint;
    document.querySelectorAll(".retry-analysis-button").forEach((button) => button.remove());
    if (chatInput && chatInput.value.trim() === retriedMessage) {
      chatInput.value = "";
      updateCharCount();
    }

    if (data.type === "follow_up" || data.type === "question") {
      if (answerToQuestion) state.followUpAnswers[answerToQuestion] = retriedMessage;
      state.pendingQuestion = data.question || data.response || "";
      addMessage("assistant", data.response || "I need a little more information.");
      renderQuestion(data.question || data.response || "Can you clarify this?", data.options || []);
      updateTelemetry(data.category || "Uncertain", data.confidence || 0, data.indicators || [], data.language, data.confidence_label);
    } else if (data.type === "final") {
      if (answerToQuestion) state.followUpAnswers[answerToQuestion] = retriedMessage;
      state.pendingQuestion = "";
      state.lastFinalReport = data;
      addMessage("assistant", data.response || "Assessment complete.");
      renderAssessment(data);
      renderLegalGuidance(data.legal_guidance || {});
      renderEvidence(data.evidence_to_preserve || data.evidence || []);
      updateTelemetry(data.category || "Uncertain", data.confidence || 0, data.indicators || [], data.language, data.confidence_label);
    }
  } catch (error) {
    addMessage(
      "assistant",
      error.message || "Analysis could not be retried. Your complaint remains saved.",
      true
    );
  } finally {
    submissionInProgress = false;
    setLoadingState(false);
  }
}

if (chatForm && chatInput) chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (submissionInProgress) return;
  const message = chatInput.value;
  if (!message.trim()) {
    return;
  }

  addMessage("user", message.trim());
  submitChatMessage(message.trim());
});

if (chatInput) chatInput.addEventListener("input", updateCharCount);

async function saveCurrentReport() {
  if (reportSaveInProgress) return;
  if (!state.lastFinalReport) {
    addMessage("assistant", "Please complete an assessment before saving a report.");
    return;
  }

  reportSaveInProgress = true;
  if (saveReportButton) saveReportButton.disabled = true;
  try {
    const response = await fetch("/reports", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        complaint: state.currentComplaint || "",
        category: state.lastFinalReport.category,
        related_category: state.lastFinalReport.related_category || "",
        confidence: state.lastFinalReport.confidence,
        urgency: state.lastFinalReport.urgency || "LOW",
        indicators: state.lastFinalReport.indicators || [],
        answers: state.followUpAnswers,
        legal_guidance: state.lastFinalReport.legal_guidance || {},
        evidence: state.lastFinalReport.evidence || [],
        next_steps: state.lastFinalReport.next_steps || [],
        session_id: state.sessionId,
        status: "Saved",
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Report could not be saved.");
    }

    state.lastFinalReport.savedReportId = data.report_id;
    addMessage("assistant", `Your report was generated successfully with ID ${data.report_ref || data.report_id}.`);
    if (viewReportButton) viewReportButton.disabled = false;
    if (downloadReportButton) downloadReportButton.disabled = false;
    if (printReportButton) printReportButton.disabled = false;
    loadReports();
  } catch (error) {
    addMessage("assistant", "I couldn't save that report right now. Please try again.");
  } finally {
    reportSaveInProgress = false;
    if (saveReportButton) {
      saveReportButton.disabled = Boolean(state.lastFinalReport?.savedReportId);
    }
  }
}

if (saveReportButton) saveReportButton.addEventListener("click", saveCurrentReport);

function startNewComplaint() {
  state.sessionId = createSessionId();
  clearActiveSessionUrl();
  state.currentComplaint = "";
  state.lastFinalReport = null;
  state.pendingQuestion = "";
  state.followUpAnswers = {};
  reportSaveInProgress = false;
  if (saveReportButton) saveReportButton.disabled = false;
  if (viewReportButton) viewReportButton.disabled = true;
  if (downloadReportButton) downloadReportButton.disabled = true;
  if (printReportButton) printReportButton.disabled = true;
  if (chatInput) {
    chatInput.value = "";
    updateCharCount();
  }
  if (chatMessages) chatMessages.replaceChildren();
  if (questionArea) questionArea.replaceChildren();
  addMessage("assistant", "Describe a new cybercrime incident or suspicious online activity.");
  if (assessmentContent) assessmentContent.textContent = "Awaiting an assessment.";
  if (legalGuidance) legalGuidance.textContent = "Legal guidance will appear here after classification.";
  if (evidenceGuide) evidenceGuide.innerHTML = "<li>Evidence recommendations will appear here.</li>";
  if (chatStatus) chatStatus.textContent = "";
  updateTelemetry("Awaiting analysis", 0, [], "Auto");
}

if (newComplaintButton) newComplaintButton.addEventListener("click", startNewComplaint);

function openSavedReport(action) {
  const reportId = state.lastFinalReport && state.lastFinalReport.savedReportId;
  if (!reportId) {
    addMessage("assistant", "Generate the report before opening it.");
    return;
  }
  const reportUrl = action === "download" ? `/report/${reportId}/download` : `/report/${reportId}`;
  if (action === "print") {
    const reportWindow = window.open(reportUrl, "_blank");
    if (reportWindow) reportWindow.addEventListener("load", () => reportWindow.print());
  } else {
    window.open(reportUrl, "_blank");
  }
}

if (viewReportButton) viewReportButton.addEventListener("click", () => openSavedReport("view"));
if (downloadReportButton) downloadReportButton.addEventListener("click", () => openSavedReport("download"));
if (printReportButton) printReportButton.addEventListener("click", () => openSavedReport("print"));

updateCharCount();
bindNavigation();
if (chatMessages) {
  if (new URLSearchParams(window.location.search).has("session_id")) {
    loadExistingChat();
  } else {
    startNewComplaint();
  }
}
loadReports();
