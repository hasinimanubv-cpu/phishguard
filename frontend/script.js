// ==========================================
// PHISHGUARD - FRONTEND SECURITY GATEWAY
// ==========================================

let statistics = {
    total: 0,
    low: 0,
    medium: 0,
    high: 0
};

let history = [];


// ==========================================
// SAFE DEMO DATA
// ==========================================

const demoMessages = {

    safe: {
        sender: "library@example.com",
        subject: "Library Reminder",

        message:
            "Your library book is due tomorrow. Please check your library account for details.",

        url: "https://example.com/library",

        score: 12,
        level: "LOW",

        indicators: [
            "No major phishing indicators detected"
        ],

        action: "ALLOW",

        explanation:
            "No major phishing indicators were identified. The message appears relatively low risk."
    },


    medium: {
        sender: "support@example.com",
        subject: "Account Notification",

        message:
            "Please review your account notification and verify your account information soon.",

        url: "https://example.com/account",

        score: 48,
        level: "MEDIUM",

        indicators: [
            "Account verification language",
            "Request for account information"
        ],

        action: "WARN",

        explanation:
            "Some suspicious characteristics were detected. Verify the sender before providing information."
    },


    high: {
        sender: "security@example.com",
        subject: "URGENT ACCOUNT VERIFICATION",

        message:
            "URGENT: Your account requires immediate verification. Please confirm your password and account credentials immediately to prevent account suspension.",

        url: "https://example.com/verify",

        score: 86,
        level: "HIGH",

        indicators: [
            "Urgent language detected",
            "Credential request detected",
            "Account suspension threat",
            "Suspicious verification request"
        ],

        action: "BLOCK",

        explanation:
            "Multiple phishing indicators were detected, including urgency, account threats, and a request for sensitive credentials."
    }

};


// ==========================================
// GET HTML ELEMENTS
// ==========================================

const sampleSelect =
    document.getElementById("sampleSelect");

const senderInput =
    document.getElementById("sender");

const subjectInput =
    document.getElementById("subject");

const messageInput =
    document.getElementById("message");

const urlInput =
    document.getElementById("url");

const scanButton =
    document.getElementById("scanButton");

const scanStatus =
    document.getElementById("scanStatus");

const riskScore =
    document.getElementById("riskScore");

const riskLevel =
    document.getElementById("riskLevel");

const scoreCircle =
    document.getElementById("scoreCircle");

const indicatorList =
    document.getElementById("indicatorList");

const indicatorCount =
    document.getElementById("indicatorCount");

const recommendedAction =
    document.getElementById("recommendedAction");

const explanationText =
    document.getElementById("explanationText");

const historyBody =
    document.getElementById("historyBody");


// ==========================================
// LOAD DEMO MESSAGE
// ==========================================

sampleSelect.addEventListener("change", function () {

    const selected = this.value;

    if (!selected) {
        return;
    }

    const data = demoMessages[selected];

    senderInput.value = data.sender;
    subjectInput.value = data.subject;
    messageInput.value = data.message;
    urlInput.value = data.url;

    resetResult();

});


// ==========================================
// RESET RESULT
// ==========================================

function resetResult() {

    riskScore.textContent = "--";

    riskLevel.textContent = "READY FOR SCAN";

    riskLevel.style.color = "";

    scoreCircle.style.borderColor = "";

    indicatorCount.textContent = "0";

    indicatorList.innerHTML = `
        <div class="empty-result">
            Ready for security analysis.
        </div>
    `;

    recommendedAction.textContent = "WAITING";

    recommendedAction.style.color = "";

    explanationText.textContent =
        "Click AUTO SCAN to begin the security assessment.";

    scanStatus.textContent = "READY";
}


// ==========================================
// AUTO SCAN
// ==========================================

scanButton.addEventListener("click", function () {

    const message =
        messageInput.value.trim();

    const url =
        urlInput.value.trim();

    if (!message) {

        alert("Please enter or select a message.");

        return;
    }

    scanButton.disabled = true;

    runSecurityScan(message, url);

});


// ==========================================
// SECURITY SCAN ANIMATION
// ==========================================

function runSecurityScan(message, url) {

    const stages = [

        "RECEIVING MESSAGE...",

        "ANALYZING MESSAGE CONTENT...",

        "CHECKING URL PATTERNS...",

        "EXTRACTING SECURITY INDICATORS...",

        "CALCULATING RISK SCORE...",

        "GENERATING THREAT ASSESSMENT..."

    ];

    let stage = 0;

    scanStatus.textContent = stages[stage];

    const interval = setInterval(() => {

        stage++;

        if (stage < stages.length) {

            scanStatus.textContent =
                stages[stage];

        }

    }, 500);


    setTimeout(() => {

        clearInterval(interval);

        const result =
            analyzeDemoMessage(message, url);

        displayResult(result);

        addToHistory(result);

        updateStatistics(result);

        scanStatus.textContent =
            "SCAN COMPLETE";

        scanButton.disabled = false;

    }, stages.length * 500 + 300);

}


// ==========================================
// TEMPORARY FRONTEND ANALYSIS
// ==========================================
// This will later be replaced by
// Chandana's Python backend API.

function analyzeDemoMessage(message, url) {

    const lowerMessage =
        message.toLowerCase();


    // Check predefined demo messages
    for (const key in demoMessages) {

        const demo =
            demoMessages[key];

        if (
            lowerMessage ===
            demo.message.toLowerCase()
        ) {

            return demo;
        }
    }


    // Temporary fallback detection

    let score = 0;

    let indicators = [];


    // --------------------------------------
    // URGENCY
    // --------------------------------------

    const urgentWords = [
        "urgent",
        "immediately",
        "asap",
        "suspended",
        "expire",
        "action required"
    ];

    if (
        urgentWords.some(word =>
            lowerMessage.includes(word)
        )
    ) {

        score += 25;

        indicators.push(
            "Urgent language detected"
        );

    }


    // --------------------------------------
    // CREDENTIAL REQUEST
    // --------------------------------------

    const credentialWords = [
        "password",
        "otp",
        "verify your account",
        "credentials",
        "login"
    ];

    if (
        credentialWords.some(word =>
            lowerMessage.includes(word)
        )
    ) {

        score += 30;

        indicators.push(
            "Credential request detected"
        );

    }


    // --------------------------------------
    // SUSPICIOUS URL
    // --------------------------------------

    if (
        url &&
        (
            url.includes("@") ||
            url.includes("login") ||
            url.includes("verify")
        )
    ) {

        score += 25;

        indicators.push(
            "Suspicious URL pattern detected"
        );

    }


    // --------------------------------------
    // THREAT LANGUAGE
    // --------------------------------------

    if (
        lowerMessage.includes("suspended") ||
        lowerMessage.includes("closed") ||
        lowerMessage.includes("blocked")
    ) {

        score += 15;

        indicators.push(
            "Account threat detected"
        );

    }


    score =
        Math.min(score, 100);


    let level;
    let action;


    if (score <= 30) {

        level = "LOW";
        action = "ALLOW";

    }

    else if (score <= 60) {

        level = "MEDIUM";
        action = "WARN";

    }

    else {

        level = "HIGH";
        action = "BLOCK";

    }


    if (indicators.length === 0) {

        indicators.push(
            "No major phishing indicators detected"
        );

    }


    return {

        score: score,

        level: level,

        indicators: indicators,

        action: action,

        explanation:
            generateExplanation(
                level,
                indicators
            )

    };

}


// ==========================================
// DISPLAY RESULT
// ==========================================

function displayResult(result) {

    riskScore.textContent =
        result.score;


    riskLevel.textContent =
        result.level + " RISK";


    recommendedAction.textContent =
        result.action;


    indicatorCount.textContent =
        result.indicators.length;


    indicatorList.innerHTML = "";


    result.indicators.forEach(indicator => {

        const item =
            document.createElement("div");

        item.className =
            "indicator";


        if (
            result.level === "HIGH" ||
            result.level === "MEDIUM"
        ) {

            item.classList.add("warning");

        }

        else {

            item.classList.add("safe");

        }


        item.textContent =
            result.level === "LOW"
                ? "✓ " + indicator
                : "⚠ " + indicator;


        indicatorList.appendChild(item);

    });


    explanationText.textContent =
        result.explanation;


    const color =
        getRiskColor(result.level);


    scoreCircle.style.borderColor =
        color;

    riskLevel.style.color =
        color;

    recommendedAction.style.color =
        color;

}


// ==========================================
// RISK COLORS
// ==========================================

function getRiskColor(level) {

    if (level === "LOW") {
        return "#39d98a";
    }

    if (level === "MEDIUM") {
        return "#f3c969";
    }

    return "#ff647c";

}


// ==========================================
// EXPLANATION
// ==========================================

function generateExplanation(
    level,
    indicators
) {

    if (level === "LOW") {

        return (
            "No major phishing indicators were identified. " +
            "The message appears relatively low risk."
        );

    }

    if (level === "MEDIUM") {

        return (
            "Some suspicious characteristics were detected. " +
            "Verify the sender before providing sensitive information."
        );

    }

    return (
        "Multiple phishing indicators were detected. " +
        "The message should be treated as high risk."
    );

}


// ==========================================
// UPDATE STATISTICS
// ==========================================

function updateStatistics(result) {

    statistics.total++;


    if (result.level === "LOW") {

        statistics.low++;

    }

    else if (result.level === "MEDIUM") {

        statistics.medium++;

    }

    else {

        statistics.high++;

    }


    document.getElementById(
        "totalScanned"
    ).textContent =
        statistics.total;


    document.getElementById(
        "lowRisk"
    ).textContent =
        statistics.low;


    document.getElementById(
        "mediumRisk"
    ).textContent =
        statistics.medium;


    document.getElementById(
        "highRisk"
    ).textContent =
        statistics.high;

}


// ==========================================
// DETECTION HISTORY
// ==========================================

function addToHistory(result) {

    const subject =
        subjectInput.value ||
        "Unknown message";


    const now =
        new Date();


    const time =
        now.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit"
        });


    history.unshift({

        time: time,

        subject: subject,

        score: result.score,

        level: result.level,

        action: result.action

    });


    renderHistory();

}


// ==========================================
// DISPLAY HISTORY
// ==========================================

function renderHistory() {

    historyBody.innerHTML = "";


    if (history.length === 0) {

        historyBody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-history">
                    No messages analyzed yet.
                </td>
            </tr>
        `;

        return;

    }


    history.forEach(item => {

        const row =
            document.createElement("tr");


        let riskClass =
            "risk-low";


        if (item.level === "MEDIUM") {
            riskClass = "risk-medium";
        }

        else if (item.level === "HIGH") {
            riskClass = "risk-high";
        }


        row.innerHTML = `

            <td>${item.time}</td>

            <td>${escapeHTML(item.subject)}</td>

            <td>${item.score}/100</td>

            <td class="${riskClass}">
                ${item.level}
            </td>

            <td class="${riskClass}">
                ${item.action}
            </td>

        `;


        historyBody.appendChild(row);

    });

}


// ==========================================
// CLEAR HISTORY
// ==========================================

document
    .getElementById("clearHistory")
    .addEventListener("click", function () {

        history = [];

        renderHistory();

    });


// ==========================================
// SECURITY: ESCAPE HTML
// ==========================================

function escapeHTML(text) {

    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}