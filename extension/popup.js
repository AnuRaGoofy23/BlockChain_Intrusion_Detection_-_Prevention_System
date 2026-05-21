// BlockShield Extension Popup UI Logic

document.addEventListener("DOMContentLoaded", () => {
    const shieldToggle = document.getElementById("shieldToggle");
    const statusText = document.getElementById("statusText");
    const statusDot = document.getElementById("statusDot");
    const statsScanned = document.getElementById("statsScanned");
    const statsBlocked = document.getElementById("statsBlocked");
    const logsList = document.getElementById("logsList");

    // Load initial state
    chrome.storage.local.get(["shieldActive", "scannedCount", "blockedCount", "logs"], (result) => {
        // Shield state
        const isActive = result.shieldActive !== false; // Default true
        shieldToggle.checked = isActive;
        updateStatusUI(isActive);

        // Stats
        statsScanned.textContent = result.scannedCount || 0;
        statsBlocked.textContent = result.blockedCount || 0;

        // Logs
        renderLogs(result.logs || []);
    });

    // Toggle Handler
    shieldToggle.addEventListener("change", () => {
        const isActive = shieldToggle.checked;
        chrome.storage.local.set({ shieldActive: isActive }, () => {
            updateStatusUI(isActive);
        });
    });

    // Status visual update
    function updateStatusUI(isActive) {
        if (isActive) {
            statusText.textContent = "ACTIVE";
            statusText.style.color = "var(--neon-aqua)";
            statusDot.style.background = "var(--neon-aqua)";
            statusDot.style.boxShadow = "var(--glow-aqua)";
        } else {
            statusText.textContent = "DEACTIVATED";
            statusText.style.color = "var(--text-dim)";
            statusDot.style.background = "var(--text-dim)";
            statusDot.style.boxShadow = "none";
        }
    }

    // Render activity list
    function renderLogs(logs) {
        if (logs.length === 0) {
            logsList.innerHTML = `<div style="padding: 12px; text-align: center; color: var(--text-dim); font-size: 11px;">No transactions scanned yet.</div>`;
            return;
        }

        logsList.innerHTML = "";
        logs.slice().reverse().forEach(log => {
            const item = document.createElement("div");
            const isBlocked = log.action === "BLOCK";
            item.className = `log-item ${isBlocked ? "block" : ""}`;

            const displayHash = log.to ? `${log.to.substring(0, 6)}...${log.to.substring(log.to.length - 4)}` : "Contract";
            const timeStr = log.time ? new Date(log.time).toLocaleTimeString() : "";

            item.innerHTML = `
                <div>
                    <span class="log-tx">${displayHash}</span>
                    <span style="color: var(--text-dim); font-size: 9px; margin-left: 4px;">${timeStr}</span>
                </div>
                <span class="log-action ${isBlocked ? "block" : ""}">${log.action}</span>
            `;
            logsList.appendChild(item);
        });
    }

    // Listen for storage changes to update UI dynamically in real-time
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.scannedCount) {
            statsScanned.textContent = changes.scannedCount.newValue;
        }
        if (changes.blockedCount) {
            statsBlocked.textContent = changes.blockedCount.newValue;
        }
        if (changes.logs) {
            renderLogs(changes.logs.newValue);
        }
    });
});
