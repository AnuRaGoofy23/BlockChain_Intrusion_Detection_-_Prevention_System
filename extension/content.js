// BlockShield Wallet Interceptor Content Script
console.log("🔐 BlockShield IPS Wallet Interceptor Active.");

// Inject script to override window.ethereum provider
const script = document.createElement("script");
script.textContent = `
  (function() {
    const originalRequest = window.ethereum ? window.ethereum.request : null;
    if (!originalRequest) return;

    window.ethereum.request = async function(args) {
      if (args && args.method === 'eth_sendTransaction') {
        const txParams = args.params[0];
        console.log("🛡️ BlockShield Intercepted proposed transaction:", txParams);

        // Notify content script to trigger BlockShield verification
        window.postMessage({
          type: "BLOCKSHIELD_PRECHECK_REQUEST",
          payload: {
            to: txParams.to,
            value: txParams.value || "0x0",
            gas: txParams.gas || "0x5208",
            data: txParams.data || "0x"
          }
        }, "*");

        // Wait for response from content script/popup
        return new Promise((resolve, reject) => {
          const handleResponse = function(event) {
            if (event.data && event.data.type === "BLOCKSHIELD_PRECHECK_RESPONSE") {
              window.removeEventListener("message", handleResponse);
              if (event.data.action === "BLOCK") {
                console.error("❌ BlockShield IPS Blocked this transaction signature!");
                reject(new Error("Transaction rejected: BlockShield IPS detected critical vulnerability."));
              } else if (event.data.action === "WARNING") {
                const confirmed = confirm("⚠️ BlockShield Warning: " + event.data.reason + "\\n\\nDo you still wish to sign this transaction?");
                if (confirmed) {
                  resolve(originalRequest.apply(window.ethereum, [args]));
                } else {
                  reject(new Error("User cancelled transaction after BlockShield security warnings."));
                }
              } else {
                console.log("✅ BlockShield: Transaction verified. Forwarding to wallet.");
                resolve(originalRequest.apply(window.ethereum, [args]));
              }
            }
          };
          window.addEventListener("message", handleResponse);
        });
      }
      return originalRequest.apply(window.ethereum, [args]);
    };
  })();
`;
try {
  document.documentElement.appendChild(script);
  script.remove();
} catch (e) {
  console.log("Failed to inject script element. Standard webpage context injection requires a page.");
}

// Listen to message from webpage to send it to the BlockShield backend
window.addEventListener("message", async (event) => {
  if (event.data && event.data.type === "BLOCKSHIELD_PRECHECK_REQUEST") {
    const payload = event.data.payload;
    
    // Retrieve shield status from extension storage
    chrome.storage.local.get(["shieldActive", "scannedCount", "blockedCount", "logs"], async (settings) => {
      const shieldActive = settings.shieldActive !== false; // default to true
      
      if (!shieldActive) {
        console.log("🛡️ BlockShield IPS: Protection bypassed (deactivated by user).");
        window.postMessage({
          type: "BLOCKSHIELD_PRECHECK_RESPONSE",
          action: "SAFE",
          reason: "Firewall protection is deactivated"
        }, "*");
        return;
      }
      
      // Call BlockShield Backend precheck endpoint
      try {
        const token = localStorage.getItem("access_token");
        const response = await fetch("http://127.0.0.1:8000/api/v1/ips/pre-check", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": token ? `Bearer ${token}` : ""
          },
          body: JSON.stringify({
            from_address: "0x0000000000000000000000000000000000000000",
            to_address: payload.to || "0x0000000000000000000000000000000000000000",
            value_eth: payload.value ? parseFloat(parseInt(payload.value, 16) / 1e18) : 0.0,
            gas_used: payload.gas ? parseFloat(parseInt(payload.gas, 16)) : 21000.0,
            token_approval_amount: payload.data && payload.data.includes("095ea7b3") ? 1000000.0 : 0.0,
            permissions: payload.data && payload.data.includes("095ea7b3") ? "Unlimited Approval" : "None"
          })
        });

        if (!response.ok) {
          throw new Error("Failed to contact BlockShield IPS service");
        }

        const result = await response.json();
        
        // Update stats and logs in extension storage
        const currentScanned = (settings.scannedCount || 0) + 1;
        const currentBlocked = (settings.blockedCount || 0) + (result.action === "BLOCK" ? 1 : 0);
        const currentLogs = settings.logs || [];
        currentLogs.push({
          to: payload.to || "0x0000000000000000000000000000000000000000",
          action: result.action,
          time: Date.now()
        });
        if (currentLogs.length > 20) currentLogs.shift(); // Keep last 20

        chrome.storage.local.set({
          scannedCount: currentScanned,
          blockedCount: currentBlocked,
          logs: currentLogs
        });
        
        // Reply back to the page
        window.postMessage({
          type: "BLOCKSHIELD_PRECHECK_RESPONSE",
          action: result.action,
          reason: result.reason
        }, "*");

      } catch (err) {
        console.warn("BlockShield IPS backend unreachable, failing safe (allowing tx):", err);
        window.postMessage({
          type: "BLOCKSHIELD_PRECHECK_RESPONSE",
          action: "SAFE",
          reason: "Unreachable IPS service"
        }, "*");
      }
    });
  }
});

