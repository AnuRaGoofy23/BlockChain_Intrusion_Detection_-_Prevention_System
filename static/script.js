// Hardcoded malicious wallet detection system configuration
const flaggedWallets = [
    "0x91E56184Da28cFCE584667387d792a48cd01ad1B" // Flagged attacker wallet address
];

// Hardcoded victim wallet configuration
const victimWallet = "0x6edb6edBe70DDcfe05478ECD18c53ce36FFbA4BC";

class BlockShieldApp {
    constructor() {
        this.token = localStorage.getItem('access_token');
        this.ws = null;
        this.chartData = Array(50).fill(15); // seed starting chart data
        this.allLogs = [];
        this.filteredLogs = [];
        this.filterMode = 'all'; // 'all' or 'anomalies'
        this.currentPrecheckLogId = null;
        
        // Webapp Secure Vault local state
        this.webappEthBalance = parseFloat(localStorage.getItem('webapp_eth_balance') || '10.0');
        this.dappRealOnlyMode = localStorage.getItem('dapp_real_only_mode') === 'true';
        this.lastPrecheckAction = null;
        this.lastPrecheckValue = 0.0;
        
        this.initDOMElements();
        this.setupAuthHandlers();
        this.setupWebappVault();
        
        if (this.token) {
            this.showDashboard();
        } else {
            this.showAuthPortal();
        }
    }

    initDOMElements() {
        // Auth panels
        this.authOverlay = document.getElementById('authOverlay');
        this.loginCard = document.getElementById('loginCard');
        this.registerCard = document.getElementById('registerCard');
        
        // Navigation links
        this.navDashboard = document.getElementById('navDashboard');
        this.navSimulator = document.getElementById('navSimulator');
        this.navAuditor = document.getElementById('navAuditor');
        this.navThreatDb = document.getElementById('navThreatDb');

        // Tab panels
        this.tabDashboard = document.getElementById('tabDashboard');
        this.tabSimulator = document.getElementById('tabSimulator');
        this.tabAuditor = document.getElementById('tabAuditor');
        this.tabThreatDb = document.getElementById('tabThreatDb');
        
        // Stats elements
        this.threatsDetectedEl = document.getElementById('threatsDetected');
        this.blockedAttacksEl = document.getElementById('blockedAttacks');
        this.activeNodesEl = document.getElementById('activeNodes');
        this.intrusionRateEl = document.getElementById('intrusionRate');
        this.highAlertPercentageEl = document.getElementById('highAlertPercentage');
        
        // Lists/Tables
        this.threatList = document.getElementById('threatList');
        this.alertsList = document.getElementById('alertsList');
        this.alertCountBadge = document.getElementById('alertCountBadge');
        this.alertCountText = document.getElementById('alertCountText');
        this.monitorTitle = document.getElementById('monitorTitle');
        
        // Chart elements
        this.avgAnomalyScoreEl = document.getElementById('avgAnomalyScore');
        this.peakAnomalyScoreEl = document.getElementById('peakAnomalyScore');
        this.avgGasUsedEl = document.getElementById('avgGasUsed');
        this.chartCanvas = document.getElementById('chartCanvas');
        
        // Classifications counts
        this.highScoreCountEl = document.getElementById('highScoreCount');
        this.medScoreCountEl = document.getElementById('medScoreCount');
        this.lowScoreCountEl = document.getElementById('lowScoreCount');
        this.noneScoreCountEl = document.getElementById('noneScoreCount');
        this.highScoreProgress = document.getElementById('highScoreProgress');
        this.medScoreProgress = document.getElementById('medScoreProgress');
        this.lowScoreProgress = document.getElementById('lowScoreProgress');
        this.noneScoreProgress = document.getElementById('noneScoreProgress');
        
        // Buttons/Forms
        this.logoutBtn = document.getElementById('logoutBtn');
        this.simulateTrafficBtn = document.getElementById('simulateTrafficBtn');
        this.simulateSpinner = document.getElementById('simulateSpinner');
        this.simulateIcon = document.getElementById('simulateIcon');
        
        this.searchForm = document.getElementById('searchForm');
        this.searchTxHash = document.getElementById('searchTxHash');
        this.searchSpinner = document.getElementById('searchSpinner');
        
        this.clearLogsBtn = document.getElementById('clearLogsBtn');
        this.notificationBtn = document.getElementById('notificationBtn');
        
        // Modal
        this.detailsModal = document.getElementById('detailsModal');
        this.closeModalBtn = document.getElementById('closeModalBtn');
        this.modalAckBtn = document.getElementById('modalAckBtn');
        this.modalTxHash = document.getElementById('modalTxHash');
        this.modalFrom = document.getElementById('modalFrom');
        this.modalTo = document.getElementById('modalTo');
        this.modalAnomalyScore = document.getElementById('modalAnomalyScore');
        this.modalSeverity = document.getElementById('modalSeverity');
        this.modalGas = document.getElementById('modalGas');
        this.modalValue = document.getElementById('modalValue');

        // Wallet connection elements
        this.connectWalletBtn = document.getElementById('connectWalletBtn');
        this.connectWalletText = document.getElementById('connectWalletText');
        this.walletInfoDisplay = document.getElementById('walletInfoDisplay');
        this.walletStatusText = document.getElementById('walletStatusText');
        this.walletAddressText = document.getElementById('walletAddressText');
        this.walletBalanceText = document.getElementById('walletBalanceText');
        this.walletNetworkText = document.getElementById('walletNetworkText');
        this.networkAlertBar = document.getElementById('networkAlertBar');
        this.currentWalletAddress = null;
        this.blockListenerProvider = null;
        this.notifiedTxHashes = new Set();

        // Wallet monitor panel elements
        this.monitorNetBadge = document.getElementById('monitorNetBadge');
        this.monitorAddress = document.getElementById('monitorAddress');
        this.monitorBalance = document.getElementById('monitorBalance');
        this.monitorBlock = document.getElementById('monitorBlock');

        // Webapp Secure Vault Elements
        this.webappVaultWindow = document.getElementById('webappVaultWindow');
        this.webappVaultBalanceText = document.getElementById('webappVaultBalanceText');
        this.vaultMinimizeBtn = document.getElementById('vaultMinimizeBtn');
        this.discreteFilterBtn = document.getElementById('discreteFilterBtn');
    }

    setupAuthHandlers() {
        // Toggle Login/Register
        document.getElementById('switchToRegister').addEventListener('click', () => {
            this.loginCard.style.display = 'none';
            this.registerCard.style.display = 'block';
        });
        document.getElementById('switchToLogin').addEventListener('click', () => {
            this.registerCard.style.display = 'none';
            this.loginCard.style.display = 'block';
        });

        // Submit Login Form
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const params = new URLSearchParams();
                params.append('username', username);
                params.append('password', password);
                
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: params
                });
                
                if (!response.ok) {
                    let errMsg = 'Authorization failed';
                    try {
                        const err = await response.json();
                        errMsg = err.detail || errMsg;
                    } catch (_) {
                        errMsg = await response.text();
                    }
                    throw new Error(errMsg);
                }
                
                const data = await response.json();
                localStorage.setItem('access_token', data.access_token);
                this.token = data.access_token;
                this.showDashboard();
            } catch (err) {
                alert('Login failed: ' + err.message);
            }
        });

        // Submit Register Form
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                if (!response.ok) {
                    let errMsg = 'Registration failed';
                    try {
                        const err = await response.json();
                        errMsg = err.detail || errMsg;
                    } catch (_) {
                        errMsg = await response.text();
                    }
                    throw new Error(errMsg);
                }
                
                const data = await response.json();
                localStorage.setItem('access_token', data.access_token);
                this.token = data.access_token;
                this.showDashboard();
            } catch (err) {
                alert('Registration failed: ' + err.message);
            }
        });

        // Logout
        this.logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('access_token');
            this.token = null;
            if (this.ws) this.ws.close();
            this.showAuthPortal();
        });
    }

    setupWebappVault() {
        if (this.webappVaultBalanceText) {
            this.webappVaultBalanceText.textContent = `${this.webappEthBalance.toFixed(4)} ETH`;
        }

        if (this.vaultMinimizeBtn && this.webappVaultWindow) {
            // Load minimize state
            const isMinimized = localStorage.getItem('webapp_vault_minimized') === 'true';
            if (isMinimized) {
                this.webappVaultWindow.classList.add('minimized');
                this.vaultMinimizeBtn.innerHTML = '&plus;';
            } else {
                this.webappVaultWindow.classList.remove('minimized');
                this.vaultMinimizeBtn.innerHTML = '&minus;';
            }

            this.vaultMinimizeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                const minimized = this.webappVaultWindow.classList.toggle('minimized');
                localStorage.setItem('webapp_vault_minimized', minimized);
                this.vaultMinimizeBtn.innerHTML = minimized ? '&plus;' : '&minus;';
            });
            
            // Also make header clickable to toggle minimize
            const header = this.webappVaultWindow.querySelector('.vault-window-header');
            if (header) {
                header.addEventListener('click', () => {
                    const minimized = this.webappVaultWindow.classList.toggle('minimized');
                    localStorage.setItem('webapp_vault_minimized', minimized);
                    this.vaultMinimizeBtn.innerHTML = minimized ? '&plus;' : '&minus;';
                });
            }
        }

        if (this.discreteFilterBtn) {
            this.discreteFilterBtn.addEventListener('click', () => {
                this.dappRealOnlyMode = !this.dappRealOnlyMode;
                localStorage.setItem('dapp_real_only_mode', this.dappRealOnlyMode);
                console.log(`[BlockShield IPS] Simulator Mode Toggled: Real-only = ${this.dappRealOnlyMode}`);
            });
        }
    }

    async fetchGanacheAccounts() {
        try {
            const response = await fetch('/api/v1/blockchain/accounts', {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    this.ganacheAccounts = data.accounts;
                    console.log('[BlockShield] Loaded Ganache accounts:', this.ganacheAccounts);
                }
            }
        } catch (err) {
            console.error('[BlockShield] Failed to fetch Ganache accounts:', err);
        }
    }

    showAuthPortal() {
        this.authOverlay.classList.remove('hidden');
        this.loginCard.style.display = 'block';
        this.registerCard.style.display = 'none';
        if (this.webappVaultWindow) {
            this.webappVaultWindow.classList.add('hidden');
        }
    }

    showDashboard() {
        this.authOverlay.classList.add('hidden');
        if (this.webappVaultWindow) {
            this.webappVaultWindow.classList.remove('hidden');
        }
        this.initDashboard();
    }

    async initDashboard() {
        this.setupNavigation();
        this.setupActionListeners();
        this.setupModalListeners();
        this.setupSimulatorController();
        this.setupAuditorController();
        this.setupThreatDbController();
        this.setupWalletConnection();
        
        // Fetch Ganache accounts for dynamic simulation targeting
        await this.fetchGanacheAccounts();
        
        // Initial Fetch
        await this.fetchLogs();
        
        // Draw real-time canvas chart
        this.startCanvasChartAnimation();
        
        // Setup WS
        this.connectWebSocket();
    }

    setupNavigation() {
        const resetNavs = () => {
            this.navDashboard.classList.remove('active');
            this.navSimulator.classList.remove('active');
            this.navAuditor.classList.remove('active');
            this.navThreatDb.classList.remove('active');

            this.tabDashboard.classList.remove('active');
            this.tabSimulator.classList.remove('active');
            this.tabAuditor.classList.remove('active');
            this.tabThreatDb.classList.remove('active');

            this.tabDashboard.style.display = 'none';
            this.tabSimulator.style.display = 'none';
            this.tabAuditor.style.display = 'none';
            this.tabThreatDb.style.display = 'none';
        };

        const setActiveTab = (navEl, tabEl) => {
            resetNavs();
            navEl.classList.add('active');
            tabEl.classList.add('active');
            tabEl.style.display = 'block';
        };

        this.navDashboard.addEventListener('click', (e) => {
            e.preventDefault();
            setActiveTab(this.navDashboard, this.tabDashboard);
            this.filterMode = 'all';
            this.monitorTitle.textContent = "Intrusion Logs & Transactions";
            this.renderLogs();
        });

        this.navSimulator.addEventListener('click', (e) => {
            e.preventDefault();
            setActiveTab(this.navSimulator, this.tabSimulator);
        });

        this.navAuditor.addEventListener('click', (e) => {
            e.preventDefault();
            setActiveTab(this.navAuditor, this.tabAuditor);
        });

        this.navThreatDb.addEventListener('click', (e) => {
            e.preventDefault();
            setActiveTab(this.navThreatDb, this.tabThreatDb);
            this.fetchThreats(); // Automatically reload threats table on tab open
        });
    }

    setupActionListeners() {
        // Traffic Simulation
        this.simulateTrafficBtn.addEventListener('click', async () => {
            this.simulateSpinner.style.display = 'inline-block';
            this.simulateIcon.style.display = 'none';
            this.simulateTrafficBtn.disabled = true;
            
            try {
                const response = await fetch('/api/v1/simulate?count=6', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${this.token}` }
                });
                if (!response.ok) {
                    if (response.status === 401) {
                        this.handleAuthExpiration();
                        return;
                    }
                    throw new Error('Simulation failed');
                }
            } catch (err) {
                alert(err.message);
            } finally {
                this.simulateSpinner.style.display = 'none';
                this.simulateIcon.style.display = 'inline-block';
                this.simulateTrafficBtn.disabled = false;
            }
        });

        // Manual Transaction Search
        this.searchForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const txHash = this.searchTxHash.value.trim();
            if (!txHash) return;
            
            this.searchSpinner.style.display = 'inline-block';
            
            try {
                const response = await fetch('/api/v1/analyze', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.token}`
                    },
                    body: JSON.stringify({ tx_hash: txHash })
                });
                
                if (!response.ok) {
                    if (response.status === 401) {
                        this.handleAuthExpiration();
                        return;
                    }
                    throw new Error('Analysis failed. Make sure server has model loaded and testnet hash is valid.');
                }
                
                const data = await response.json();
                
                // Show modal with results
                this.openInspectModal({
                    tx_hash: data.tx_hash,
                    from_address: '0x' + Array(40).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''), // Mocked for test UI
                    to_address: '0x' + Array(40).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''),
                    anomaly_score: data.anomaly_score,
                    severity: data.severity,
                    gas_used: 120000,
                    value_eth: 1.25
                });
                
                this.fetchLogs(); // refresh logs list
            } catch (err) {
                alert(err.message);
            } finally {
                this.searchSpinner.style.display = 'none';
            }
        });

        // Clear/Refresh Logs Button
        this.clearLogsBtn.addEventListener('click', () => {
            this.fetchLogs();
        });

        // Notification clicks
        this.notificationBtn.addEventListener('click', () => {
            const count = this.allLogs.filter(l => l.severity !== 'Low Risk' && l.severity !== 'NONE').length;
            alert(`IDS Log Audit: ${count} total anomalies detected by AI Isolation Forest.`);
        });
    }

    setupModalListeners() {
        this.closeModalBtn.addEventListener('click', () => {
            this.detailsModal.classList.remove('active');
        });
        
        this.modalAckBtn.addEventListener('click', () => {
            this.detailsModal.classList.remove('active');
        });
        
        // Close modal on click outside
        this.detailsModal.addEventListener('click', (e) => {
            if (e.target === this.detailsModal) {
                this.detailsModal.classList.remove('active');
            }
        });
    }

    setupSimulatorController() {
        const simTxForm = document.getElementById('simTxForm');
        const dappTriggerBtn = document.getElementById('dappTriggerBtn');
        const simDomain = document.getElementById('simDomain');
        const browserUrlText = document.getElementById('browserUrlText');
        const walletCancelBtn = document.getElementById('walletCancelBtn');
        const walletConfirmBtn = document.getElementById('walletConfirmBtn');
        
        // Instantly sync URL bar in browser mockup when editing Associated Domain
        if (simDomain && browserUrlText) {
            simDomain.addEventListener('input', () => {
                const domain = simDomain.value.trim() || 'wallet-portal.dapp';
                browserUrlText.textContent = domain.startsWith('http') ? domain : `http://${domain}`;
            });
        }

        // Handle transaction precheck submission
        if (simTxForm) {
            simTxForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.triggerPreCheck({
                    from_address: document.getElementById('simFrom').value,
                    to_address: document.getElementById('simTo').value,
                    value_eth: parseFloat(document.getElementById('simValue').value) || 0.0,
                    gas_used: parseInt(document.getElementById('simGasLimit').value) || 120000,
                    gas_price_gwei: parseFloat(document.getElementById('simGasPrice').value) || 35.0,
                    permissions: document.getElementById('simPermissions').value,
                    token_approval_amount: parseFloat(document.getElementById('simApprovalAmount').value) || 0.0,
                    wallet_age_days: parseInt(document.getElementById('simWalletAge').value) || 145,
                    failed_tx_count: parseInt(document.getElementById('simFailedCount').value) || 0,
                    associated_domain: document.getElementById('simDomain').value
                });
            });
        }

        // Web Sandbox Button Trigger with 3-second delay/cooldown and random safe/scam addresses
        if (dappTriggerBtn) {
            dappTriggerBtn.addEventListener('click', () => {
                if (dappTriggerBtn.classList.contains('cooldown')) return;

                // Determine transaction type (if real-only is toggled, always real; otherwise 30% chance real, 70% chance scam)
                const isReal = this.dappRealOnlyMode ? true : (Math.random() < 0.3);
                
                // Disable button and start 3-second cooldown countdown
                dappTriggerBtn.classList.add('cooldown');
                dappTriggerBtn.disabled = true;
                
                let countdown = 3;
                dappTriggerBtn.textContent = `Scanning (${countdown}s)...`;
                
                const timer = setInterval(() => {
                    countdown--;
                    if (countdown > 0) {
                        dappTriggerBtn.textContent = `Scanning (${countdown}s)...`;
                    } else {
                        clearInterval(timer);
                        dappTriggerBtn.classList.remove('cooldown');
                        dappTriggerBtn.disabled = false;
                        dappTriggerBtn.textContent = 'Verify & Claim Rewards';
                        
                        // Generate transaction details using realistic random hashes
                        const randomAddress = () => '0x' + Array(40).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join('');
                        
                        if (isReal) {
                            // Populate form with real transaction parameters
                            const val = (0.01 + Math.random() * 0.08).toFixed(4);
                            
                            // Dynamically find a recipient account from Ganache accounts
                            let recipient = '';
                            if (this.ganacheAccounts && this.ganacheAccounts.length > 0) {
                                const otherAccounts = this.ganacheAccounts.filter(addr => 
                                    !this.currentWalletAddress || addr.toLowerCase() !== this.currentWalletAddress.toLowerCase()
                                );
                                if (otherAccounts.length > 0) {
                                    recipient = otherAccounts[0]; // Send to Wallet B (real account)
                                } else {
                                    recipient = this.ganacheAccounts[0];
                                }
                            } else {
                                recipient = '0x6edb6edBe70DDcfe05478ECD18c53ce36FFbA4BC'; // Default fallback
                            }
                            
                            const fromAddr = this.currentWalletAddress || '0x71C7656EC7ab88b098defB751B7401B5f6d8976F';
                            
                            document.getElementById('simFrom').value = fromAddr;
                            document.getElementById('simTo').value = recipient;
                            document.getElementById('simValue').value = val;
                            document.getElementById('simGasLimit').value = '21000';
                            document.getElementById('simGasPrice').value = '25';
                            document.getElementById('simPermissions').value = 'None';
                            document.getElementById('simApprovalAmount').value = '0';
                            document.getElementById('simWalletAge').value = '245';
                            document.getElementById('simFailedCount').value = '0';
                            document.getElementById('simDomain').value = 'safepool-staking.net';
                            
                            if (browserUrlText) {
                                browserUrlText.textContent = 'http://safepool-staking.net';
                            }
                        } else {
                            // Populate form with simulated scam parameters
                            const scamRecipient = randomAddress();
                            const fromAddr = this.currentWalletAddress || '0x71C7656EC7ab88b098defB751B7401B5f6d8976F';
                            
                            document.getElementById('simFrom').value = fromAddr;
                            document.getElementById('simTo').value = scamRecipient;
                            document.getElementById('simValue').value = '0.025';
                            document.getElementById('simGasLimit').value = '180000';
                            document.getElementById('simGasPrice').value = '45';
                            document.getElementById('simPermissions').value = 'Unlimited Approval';
                            document.getElementById('simApprovalAmount').value = '100000000';
                            document.getElementById('simWalletAge').value = '1';
                            document.getElementById('simFailedCount').value = '3';
                            document.getElementById('simDomain').value = 'blockshield-verify.io';
                            
                            if (browserUrlText) {
                                browserUrlText.textContent = 'http://blockshield-verify.io';
                            }
                        }
                        
                        // Submit simulated tx
                        simTxForm.dispatchEvent(new Event('submit'));
                    }
                }, 1000);
            });
        }

        // Reject / Cancel button logic
        if (walletCancelBtn) {
            walletCancelBtn.addEventListener('click', () => {
                document.getElementById('walletOverlay').style.display = 'none';
            });
        }

        // MetaMask Confirm Sign Button Click (reducing Webapp Vault ETH balance and sending REAL transaction via MetaMask/Ganache)
        if (walletConfirmBtn) {
            walletConfirmBtn.addEventListener('click', async () => {
                if (!this.currentPrecheckLogId) return;
                
                walletConfirmBtn.disabled = true;
                walletConfirmBtn.innerHTML = '<span class="mini-spinner"></span> Signing...';
                
                // If it is a real transaction and we have MetaMask connected, trigger a real transaction broadcast!
                let txHash = null;
                if (this.lastPrecheckAction === 'SAFE' && window.ethereum && this.currentWalletAddress) {
                    try {
                        const provider = new ethers.BrowserProvider(window.ethereum);
                        const signer = await provider.getSigner();
                        
                        const valueEth = parseFloat(document.getElementById('simValue').value) || 0.05;
                        const toAddress = document.getElementById('simTo').value;
                        const gasLimit = parseInt(document.getElementById('simGasLimit').value) || 21000;
                        
                        walletConfirmBtn.innerHTML = '<span class="mini-spinner"></span> Confirming in MetaMask...';
                        
                        const tx = await signer.sendTransaction({
                            to: toAddress,
                            value: ethers.parseEther(valueEth.toString()),
                            gasLimit: gasLimit
                        });
                        
                        walletConfirmBtn.innerHTML = '<span class="mini-spinner"></span> Waiting for mining...';
                        const receipt = await tx.wait();
                        txHash = receipt.hash;
                        console.log("[BlockShield] Real transaction broadcasted and mined! Hash:", txHash);
                    } catch (txErr) {
                        console.error("[BlockShield] Real MetaMask transaction failed or rejected:", txErr);
                        alert('Transaction was rejected or failed in MetaMask: ' + (txErr.message || txErr.reason || txErr));
                        walletConfirmBtn.textContent = 'Sign';
                        walletConfirmBtn.disabled = false;
                        return; // Stop and do not call backend confirm if real transaction fails
                    }
                }
                
                try {
                    const response = await fetch('/api/v1/ips/confirm', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${this.token}`
                        },
                        body: JSON.stringify({ log_id: this.currentPrecheckLogId })
                    });
                    
                    if (!response.ok) {
                        throw new Error('Signature confirmation request failed.');
                    }
                    
                    // Deduct balance if the prechecked transaction was SAFE
                    if (this.lastPrecheckAction === 'SAFE' && typeof this.lastPrecheckValue === 'number') {
                        this.webappEthBalance = Math.max(0.0, this.webappEthBalance - this.lastPrecheckValue);
                        localStorage.setItem('webapp_eth_balance', this.webappEthBalance.toString());
                        
                        // Update balance UI with flash effect
                        if (this.webappVaultBalanceText) {
                            this.webappVaultBalanceText.textContent = `${this.webappEthBalance.toFixed(4)} ETH`;
                            this.webappVaultBalanceText.classList.remove('deduct-flash');
                            void this.webappVaultBalanceText.offsetWidth; // Trigger reflow
                            this.webappVaultBalanceText.classList.add('deduct-flash');
                        }
                    }
                    
                    alert('Signature authorization confirmed. Transaction dispatched to the blockchain network.');
                } catch (err) {
                    console.error(err);
                    alert('Signature accepted locally.');
                } finally {
                    walletConfirmBtn.textContent = 'Sign';
                    walletConfirmBtn.disabled = false;
                    document.getElementById('walletOverlay').style.display = 'none';
                    await this.fetchLogs(); // refresh tables and counts
                }
            });
        }
    }

    async triggerPreCheck(payload) {
        const overlay = document.getElementById('walletOverlay');
        const targetText = document.getElementById('walletTargetText');
        const valueText = document.getElementById('walletValueText');
        const ipsLoading = document.getElementById('ipsLoading');
        const ipsResult = document.getElementById('ipsResult');
        const ipsStatusBadge = document.getElementById('ipsStatusBadge');
        const ipsReasonText = document.getElementById('ipsReasonText');
        const ipsScoreText = document.getElementById('ipsScoreText');
        const warningBanner = document.getElementById('walletWarningBanner');
        const acceptCheckbox = document.getElementById('walletAcceptWarning');
        const confirmBtn = document.getElementById('walletConfirmBtn');

        // Setup display mockup
        targetText.textContent = payload.to_address.substring(0, 6) + '...' + payload.to_address.substring(payload.to_address.length - 4);
        valueText.textContent = payload.value_eth + ' ETH';
        overlay.style.display = 'flex';
        ipsLoading.style.display = 'flex';
        ipsResult.style.display = 'none';
        warningBanner.style.display = 'none';
        acceptCheckbox.checked = false;
        confirmBtn.disabled = true;

        this.currentPrecheckLogId = null;

        try {
            const response = await fetch('/api/v1/ips/pre-check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                if (response.status === 401) {
                    this.handleAuthExpiration();
                    return;
                }
                throw new Error('Failed to run intrusion prevention pre-check');
            }

            const data = await response.json();
            this.currentPrecheckLogId = data.log_id;
            this.lastPrecheckAction = data.action;
            this.lastPrecheckValue = payload.value_eth;

            // Artificial delay to simulate scanning
            await new Promise(resolve => setTimeout(resolve, 1500));

            ipsLoading.style.display = 'none';
            ipsResult.style.display = 'block';
            ipsScoreText.textContent = data.risk_score;
            ipsReasonText.textContent = data.reason;

            // Set badge status details
            ipsStatusBadge.textContent = data.action;
            ipsStatusBadge.className = 'ips-status-badge'; // reset

            if (data.action === 'SAFE') {
                ipsStatusBadge.classList.add('safe');
                confirmBtn.disabled = false;
            } else if (data.action === 'WARNING') {
                ipsStatusBadge.classList.add('warning');
                warningBanner.style.display = 'block';
                confirmBtn.disabled = true; // Sign button remains locked until checkbox ticked

                acceptCheckbox.onchange = () => {
                    confirmBtn.disabled = !acceptCheckbox.checked;
                };
            } else if (data.action === 'BLOCK') {
                ipsStatusBadge.classList.add('blocked');
                confirmBtn.disabled = true; // Permanently disabled signature button
            }
        } catch (err) {
            console.error(err);
            ipsLoading.style.display = 'none';
            ipsResult.style.display = 'block';
            ipsStatusBadge.textContent = 'OFFLINE';
            ipsStatusBadge.className = 'ips-status-badge blocked';
            ipsReasonText.textContent = 'System pre-check connection failure.';
            ipsScoreText.textContent = '99';
            confirmBtn.disabled = true;
        }
    }

    setupAuditorController() {
        const templates = {
            reentrancy: `pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0);

        // VULNERABILITY: State transfer happens before account balance reset
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }
}`,
            selfdestruct: `pragma solidity ^0.8.0;

contract UnprotectedGame {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: Public closeGame exposes selfdestruct execution
    function closeGame() public {
        selfdestruct(payable(owner));
    }
}`,
            approval: `pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract TokenSpender {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function approveInfinite(address spender) public {
        // VULNERABILITY: Approving infinite tokens is risky
        token.approve(spender, type(uint256).max);
    }
}`,
            safe: `pragma solidity ^0.8.0;

contract SafeStore {
    address public owner;
    mapping(address => uint256) private _vault;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        _vault[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(_vault[msg.sender] >= amount, "Insufficient balance");
        _vault[msg.sender] -= amount;
        
        // SAFE: follows checks-effects-interactions pattern
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}`
        };

        const templateSelect = document.getElementById('contractTemplateSelect');
        const contractCodeInput = document.getElementById('contractCode');
        const analyzeContractBtn = document.getElementById('analyzeContractBtn');
        const auditorSpinner = document.getElementById('auditorSpinner');
        
        if (templateSelect && contractCodeInput) {
            templateSelect.addEventListener('change', () => {
                const val = templateSelect.value;
                if (val && templates[val]) {
                    contractCodeInput.value = templates[val];
                }
            });
        }

        if (analyzeContractBtn && contractCodeInput) {
            analyzeContractBtn.addEventListener('click', async () => {
                const code = contractCodeInput.value.trim();
                if (!code) {
                    alert('Please load a solidity contract template or write custom code before auditing.');
                    return;
                }

                if (auditorSpinner) auditorSpinner.style.display = 'inline-block';
                analyzeContractBtn.disabled = true;

                try {
                    const response = await fetch('/api/v1/ips/analyze-contract', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${this.token}`
                        },
                        body: JSON.stringify({ code: code })
                    });

                    if (!response.ok) {
                        if (response.status === 401) {
                            this.handleAuthExpiration();
                            return;
                        }
                        throw new Error('Solidity static analysis failed.');
                    }

                    const data = await response.json();
                    this.renderAuditFindings(data);
                } catch (err) {
                    alert(err.message);
                } finally {
                    if (auditorSpinner) auditorSpinner.style.display = 'none';
                    analyzeContractBtn.disabled = false;
                }
            });
        }
    }

    renderAuditFindings(data) {
        const summaryBadge = document.getElementById('auditorSummaryBadge');
        const summaryStats = document.getElementById('auditorSummaryStats');
        const critCount = document.getElementById('auditorCritCount');
        const highCount = document.getElementById('auditorHighCount');
        const medCount = document.getElementById('auditorMedCount');
        const findingsList = document.getElementById('findingsList');
        
        findingsList.innerHTML = '';
        
        if (data.findings.length === 0) {
            summaryBadge.textContent = 'SECURE';
            summaryBadge.className = 'badge success';
            summaryStats.style.display = 'none';
            findingsList.innerHTML = `
                <div style="padding: 2.5rem; text-align: center; color: #00ff88; background: rgba(0, 255, 136, 0.05); border: 1px dashed rgba(0, 255, 136, 0.2); border-radius: 1rem;">
                    <span style="font-size: 2rem;">🛡️</span>
                    <h4 style="margin: 0.5rem 0 0.25rem 0; font-weight: bold;">No Security Flaws Found</h4>
                    <p style="font-size: 0.8rem; color: var(--text-secondary); margin: 0;">This smart contract passed all BlockShield static check heuristics.</p>
                </div>
            `;
            return;
        }
        
        summaryBadge.textContent = 'VULNERABLE';
        summaryBadge.className = 'badge critical';
        summaryStats.style.display = 'grid';
        
        critCount.textContent = data.summary.critical;
        highCount.textContent = data.summary.high;
        medCount.textContent = data.summary.medium;
        
        data.findings.forEach(f => {
            const item = document.createElement('div');
            // Mapping criticalities to CSS styles
            let classSev = f.severity;
            if (f.severity === 'High Risk') classSev = 'High_Risk';
            else if (f.severity === 'Medium Risk') classSev = 'Medium_Risk';

            item.className = `finding-item ${classSev}`;
            
            let remediation = '';
            if (f.type === 'Reentrancy Vulnerability') {
                remediation = 'Remediation: Follow checks-effects-interactions pattern. Update internal states before initiating external ether/token transfers.';
            } else if (f.type === 'Unprotected Selfdestruct') {
                remediation = 'Remediation: Secure destruction functionality. Bind the selfdestruct execution using owners/admin role modifiers.';
            } else if (f.type === 'Missing Access Control') {
                remediation = 'Remediation: Restrict modifiers. Implement dynamic address identity validation assertions.';
            } else {
                remediation = 'Remediation: Practice allowance caps. Require explicit approval parameters matching target requirements.';
            }

            item.innerHTML = `
                <div class="finding-item-header">
                    <span class="finding-title">${f.type}</span>
                    <span class="finding-line">Line ${f.line}</span>
                </div>
                <div class="finding-desc">${f.description}</div>
                <code style="display: block; font-family: monospace; font-size: 0.8rem; background: rgba(0,0,0,0.3); padding: 0.45rem; border-radius: 0.25rem; margin-bottom: 0.5rem; border: 1px solid rgba(255,255,255,0.05); color: #f43f5e; overflow-x: auto;">${f.code_snippet}</code>
                <div class="finding-remediation">${remediation}</div>
            `;
            findingsList.appendChild(item);
        });
    }

    setupThreatDbController() {
        const addThreatForm = document.getElementById('addThreatForm');
        const threatAddSpinner = document.getElementById('threatAddSpinner');

        if (addThreatForm) {
            addThreatForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const type = document.getElementById('threatType').value;
                const value = document.getElementById('threatValue').value.trim();
                const desc = document.getElementById('threatDescription').value.trim();
                const severity = document.getElementById('threatSeverity').value;

                if (threatAddSpinner) threatAddSpinner.style.display = 'inline-block';

                try {
                    const response = await fetch('/api/v1/threats', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${this.token}`
                        },
                        body: JSON.stringify({
                            entity_type: type,
                            value: value,
                            description: desc,
                            severity: severity
                        })
                    });

                    if (!response.ok) {
                        if (response.status === 401) {
                            this.handleAuthExpiration();
                            return;
                        }
                        const err = await response.json();
                        throw new Error(err.detail || 'Registry failed.');
                    }

                    // Reset form
                    document.getElementById('threatValue').value = '';
                    document.getElementById('threatDescription').value = '';

                    // Reload
                    await this.fetchThreats();
                } catch (err) {
                    alert(err.message);
                } finally {
                    if (threatAddSpinner) threatAddSpinner.style.display = 'none';
                }
            });
        }
    }

    setupWalletConnection() {
        if (!this.connectWalletBtn) return;

        // Check if MetaMask is installed
        if (typeof window.ethereum === 'undefined') {
            console.log('MetaMask not detected.');
            this.updateWalletUI(null, null);
            this.connectWalletBtn.addEventListener('click', () => {
                alert('MetaMask is not installed. Please install the MetaMask extension to use wallet features!');
            });
            return;
        }

        // Setup click listener for Connect Wallet button
        this.connectWalletBtn.addEventListener('click', async () => {
            if (this.connectWalletBtn.classList.contains('connected')) {
                this.disconnectWallet();
            } else {
                await this.connectWallet();
            }
        });

        // Setup MetaMask event listeners
        window.ethereum.on('accountsChanged', (accounts) => {
            console.log('MetaMask account changed:', accounts);
            if (accounts.length === 0) {
                this.currentWalletAddress = null;
                if (this.blockListenerProvider) {
                    try {
                        this.blockListenerProvider.removeAllListeners("block");
                    } catch (e) {
                        console.error("Error removing block listeners on accountsChanged:", e);
                    }
                    this.blockListenerProvider = null;
                }
                this.updateWalletUI(null, null);
            } else {
                this.fetchWalletDetails(accounts[0]);
            }
        });

        window.ethereum.on('chainChanged', (chainId) => {
            console.log('MetaMask network changed:', chainId);
            window.location.reload();
        });

        // Automatically detect if wallet is already connected on reload
        this.checkAlreadyConnected();
    }

    async checkAlreadyConnected() {
        try {
            const provider = new ethers.BrowserProvider(window.ethereum);
            const accounts = await provider.send('eth_accounts', []);
            if (accounts.length > 0) {
                console.log('Detected existing MetaMask connection:', accounts[0]);
                await this.fetchWalletDetails(accounts[0]);
            } else {
                this.updateWalletUI(null, null);
            }
        } catch (err) {
            console.error('Error checking existing wallet connection:', err);
            this.updateWalletUI(null, null);
        }
    }

    async connectWallet() {
        if (!window.ethereum) return;
        
        this.connectWalletBtn.disabled = true;
        const originalText = this.connectWalletText.textContent;
        this.connectWalletText.textContent = 'Connecting...';

        try {
            const provider = new ethers.BrowserProvider(window.ethereum);
            const accounts = await provider.send('eth_requestAccounts', []);
            
            if (accounts.length > 0) {
                await this.fetchWalletDetails(accounts[0]);
            } else {
                throw new Error('No accounts returned from MetaMask.');
            }
        } catch (err) {
            console.error('MetaMask connection error:', err);
            if (err.code === 4001) {
                alert('Connection request rejected. Please authorize MetaMask connectivity to access dashboard features!');
            } else if (err.code === -32002) {
                alert('Connection request already pending in MetaMask. Please open the MetaMask extension and approve.');
            } else {
                alert('Failed to connect MetaMask: ' + (err.message || err));
            }
            this.updateWalletUI(null, null);
        } finally {
            this.connectWalletBtn.disabled = false;
            this.connectWalletText.textContent = this.connectWalletBtn.classList.contains('connected') ? 'Disconnect' : originalText;
        }
    }

    async fetchWalletDetails(address) {
        if (!address) return;
        this.currentWalletAddress = address;

        // Set Loading state
        this.walletBalanceText.className = 'wallet-bal loading';
        this.walletBalanceText.textContent = 'Loading...';
        if (this.walletNetworkText) {
            this.walletNetworkText.textContent = 'Detecting...';
            this.walletNetworkText.style.color = 'var(--text-dim)';
        }

        try {
            const provider = new ethers.BrowserProvider(window.ethereum);
            const network = await provider.getNetwork();
            const chainId = Number(network.chainId);
            const isGanache = chainId === 1337 || chainId === 5777;

            // Network validation display
            if (this.networkAlertBar) {
                this.networkAlertBar.style.display = isGanache ? 'none' : 'block';
            }

            let networkName = 'Unknown Network';
            if (chainId === 1) networkName = 'Ethereum Mainnet';
            else if (chainId === 11155111) networkName = 'Sepolia Testnet';
            else if (chainId === 1337) networkName = 'Ganache (1337)';
            else if (chainId === 5777) networkName = 'Ganache (5777)';
            else networkName = `Chain ID: ${chainId}`;

            const balance = await provider.getBalance(address);
            const formattedBalance = parseFloat(ethers.formatEther(balance)).toFixed(4);

            this.updateWalletUI(address, formattedBalance, networkName, isGanache);
            this.setupBlockListener(provider, address);
        } catch (err) {
            console.error('Failed to retrieve wallet details:', err);
            this.walletBalanceText.className = 'wallet-bal error';
            this.walletBalanceText.textContent = 'Error';
            if (this.walletNetworkText) {
                this.walletNetworkText.textContent = 'Failed to fetch';
                this.walletNetworkText.style.color = 'var(--rose-pink)';
            }
            this.updateWalletUI(address, 'Error', 'Error', false);
        }
    }

    setupBlockListener(provider, address) {
        if (this.blockListenerProvider) {
            try {
                this.blockListenerProvider.removeAllListeners("block");
            } catch (e) {
                console.error("Error clearing previous block listener:", e);
            }
        }
        this.blockListenerProvider = provider;
        try {
            provider.on("block", async (blockNumber) => {
                console.log("New block mined, refreshing balance & scanning transactions:", blockNumber);
                if (this.currentWalletAddress === address) {
                    try {
                        const balance = await provider.getBalance(address);
                        const formattedBalance = parseFloat(ethers.formatEther(balance)).toFixed(4);
                        this.walletBalanceText.className = 'wallet-bal';
                        this.walletBalanceText.textContent = `${formattedBalance} ETH`;

                        // Update dedicated wallet monitor panel
                        if (this.monitorBalance) this.monitorBalance.textContent = `${formattedBalance} ETH`;
                        if (this.monitorBlock) this.monitorBlock.textContent = `#${blockNumber}`;

                        // Scan transactions in the newly mined block in real-time
                        const block = await provider.getBlock(blockNumber);
                        if (block && block.transactions) {
                            for (const txHash of block.transactions) {
                                try {
                                    // Prevent duplicate notifications
                                    if (this.notifiedTxHashes.has(txHash)) continue;
                                    this.notifiedTxHashes.add(txHash);

                                    const tx = await provider.getTransaction(txHash);
                                    if (tx) {
                                        // Capture transactions involving our Ganache accounts
                                        const isFromMe = tx.from && tx.from.toLowerCase() === address.toLowerCase();
                                        const isToMe = tx.to && tx.to.toLowerCase() === address.toLowerCase();
                                        const isToVictim = tx.to && tx.to.toLowerCase() === victimWallet.toLowerCase();
                                        const isToGanache = tx.to && this.ganacheAccounts && this.ganacheAccounts.some(a => a.toLowerCase() === tx.to.toLowerCase());

                                        if (isFromMe || isToMe || isToVictim || isToGanache) {
                                            await this.handleIncomingTransaction(tx);
                                        }
                                    }
                                } catch (txErr) {
                                    console.error("Error fetching transaction details for hash " + txHash + ":", txErr);
                                }
                            }
                        }
                    } catch (e) {
                        console.error("Failed to refresh balance or scan block:", e);
                        // Fallback to random balance
                        if (!this.fallbackBalance) {
                            this.fallbackBalance = (10 + Math.random() * 90).toFixed(4);
                        }
                        if (this.monitorBalance) this.monitorBalance.textContent = `${this.fallbackBalance} ETH`;
                        if (this.monitorBlock) this.monitorBlock.textContent = `#${blockNumber}`;
                    }
                }
            });
        } catch (e) {
            console.error("Failed to set block listener:", e);
        }
    }

    async handleIncomingTransaction(tx) {
        const sender = tx.from;
        const amountStr = parseFloat(ethers.formatEther(tx.value)).toFixed(4);
        const timeStr = new Date().toLocaleString();
        
        // Clean Logging for incoming transactions
        console.log(`%c📥 [INCOMING TRANSACTION] Mined in block! Hash: ${tx.hash} | Sender: ${sender} | Amount: ${amountStr} ETH`, 'color: #00ffff; font-weight: bold;');
        
        // Check if sender is flagged as malicious
        const isFlagged = flaggedWallets.some(addr => addr.toLowerCase() === sender.toLowerCase());
        
        const txLog = {
            id: Date.now(),
            tx_hash: tx.hash,
            gas_used: Number(tx.gasLimit || 21000n),
            gas_fee_eth: tx.gasPrice ? parseFloat(ethers.formatEther(tx.gasPrice * (tx.gasLimit || 21000n))) : 0.0001,
            value_eth: parseFloat(ethers.formatEther(tx.value)),
            from_address: sender,
            to_address: tx.to,
            anomaly_score: isFlagged ? 0.995 : 0.002,
            severity: isFlagged ? 'Critical' : 'Low Risk',
            mempool_status: isFlagged ? 'blocked' : 'confirmed',
            timestamp: new Date().toISOString()
        };

        if (isFlagged) {
            // Clean Logging for blocked transaction & suspicious wallet activity
            console.warn(`%c⚠️ [SUSPICIOUS WALLET ACTIVITY] Transaction originated from flagged malicious wallet: ${sender}`, 'color: #eab308; font-weight: bold;');
            console.error(`%c🚫 [TRANSACTION BLOCKED] BlockShield transaction gateway firewall blocked the interaction!`, 'color: #f43f5e; font-weight: bold;');
            
            // Add a local blocked record to the dashboard log list so it is visually updated
            this.allLogs.unshift(txLog);
            this.calculateMetrics();
            this.renderLogs();
            
            // Trigger security alert popup & block interface
            this.showSecurityAlertPopup(tx, amountStr, timeStr);
        } else {
            // Standard incoming transaction
            this.allLogs.unshift(txLog);
            this.calculateMetrics();
            this.renderLogs();
            
            // Show real-time notification popup on website
            this.showIncomingTxNotification(txLog, amountStr, timeStr);
        }
    }

    showIncomingTxNotification(txLog, amountStr, timeStr) {
        // Create popup container if it doesn't exist
        let container = document.getElementById('blockchain-notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'blockchain-notification-container';
            document.body.appendChild(container);
        }
        
        const popup = document.createElement('div');
        popup.className = 'incoming-tx-popup';
        
        popup.innerHTML = `
            <div class="incoming-tx-header">
                <span class="incoming-tx-icon">📥</span>
                <span class="incoming-tx-title">Transaction Detected</span>
                <span class="threat-badge ${this.getBadgeClass(txLog.severity)}" style="font-size: 0.65rem; padding: 2px 6px; margin-left: auto;">${txLog.severity}</span>
            </div>
            <div class="incoming-tx-body">
                <div><strong>Sender:</strong> <span class="tx-addr" title="${txLog.from_address}">${txLog.from_address.substring(0, 6)}...${txLog.from_address.substring(txLog.from_address.length - 4)}</span></div>
                <div><strong>Amount:</strong> <span class="tx-amount">${amountStr} ETH</span></div>
                <div><strong>Time:</strong> <span class="tx-time">${timeStr}</span></div>
            </div>
            <div class="incoming-tx-actions" style="margin-top: 10px; display: flex; gap: 8px; justify-content: flex-end;">
                <button class="btn-small ack-btn" style="padding: 2px 8px; font-size: 0.75rem; background: rgba(255,255,255,0.05); color: #fff; border-color: rgba(255,255,255,0.1);">Dismiss</button>
                <button class="btn-small inspect-btn" style="padding: 2px 8px; font-size: 0.75rem;">Inspect</button>
            </div>
        `;
        
        container.appendChild(popup);
        
        // Setup Actions
        const ackBtn = popup.querySelector('.ack-btn');
        const inspectBtn = popup.querySelector('.inspect-btn');
        
        ackBtn.addEventListener('click', () => {
            popup.classList.add('fade-out');
            setTimeout(() => popup.remove(), 500);
        });
        
        inspectBtn.addEventListener('click', () => {
            popup.remove();
            this.openInspectModal(txLog);
        });
        
        // Auto-remove after 10 seconds if not clicked
        setTimeout(() => {
            if (popup.parentElement) {
                popup.classList.add('fade-out');
                setTimeout(() => popup.remove(), 500);
            }
        }, 10000);
    }

    showSecurityAlertPopup(tx, amountStr, timeStr) {
        // Close any active simulator signing flow
        const walletOverlay = document.getElementById('walletOverlay');
        if (walletOverlay) {
            walletOverlay.style.display = 'none';
        }
        this.currentPrecheckLogId = null;
        
        // Create alert modal overlay
        const alertOverlay = document.createElement('div');
        alertOverlay.id = 'security-alert-overlay';
        alertOverlay.className = 'security-alert-overlay';
        
        alertOverlay.innerHTML = `
            <div class="security-alert-modal">
                <div class="security-alert-icon">⚠️</div>
                <h2>High Risk Wallet Detected</h2>
                <div class="security-alert-subtitle">Known Scam Address</div>
                
                <div class="security-alert-details">
                    <p><strong>Attacker Address:</strong> <code class="security-code">${tx.from}</code></p>
                    <p><strong>Amount Sent:</strong> <span>${amountStr} ETH</span></p>
                    <p><strong>Timestamp:</strong> <span>${timeStr}</span></p>
                </div>
                
                <div class="security-alert-score-container">
                    <div class="security-alert-score-label">Risk Score</div>
                    <div class="security-alert-score-value">99/100</div>
                </div>
                
                <div class="security-alert-status">
                    <span>Transaction Blocked</span>
                </div>
                
                <div class="security-alert-footer">
                    BlockShield Firewall has locked interaction to protect your assets.
                </div>
                <button class="security-alert-unlock-btn" onclick="window.location.reload()">Reset Firewall & Reconnect</button>
            </div>
        `;
        
        document.body.appendChild(alertOverlay);
        
        // Block further transaction interaction by injecting a blocking CSS class/overlay
        document.body.classList.add('firewall-blocked');
        
        // Disable interactive elements on the page
        this.disableAllInteractions();
    }

    disableAllInteractions() {
        // Disable all inputs, selects, textareas, and buttons across all forms
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const inputs = form.querySelectorAll('input, select, textarea, button');
            inputs.forEach(input => input.disabled = true);
        });
        
        // Disable all buttons on the page
        const buttons = document.querySelectorAll('button');
        buttons.forEach(button => {
            if (!button.classList.contains('security-alert-unlock-btn')) {
                button.disabled = true;
                button.style.opacity = '0.5';
                button.style.pointerEvents = 'none';
            }
        });
        
        // Block simulator triggers
        const dappTriggerBtn = document.getElementById('dappTriggerBtn');
        if (dappTriggerBtn) {
            dappTriggerBtn.disabled = true;
            dappTriggerBtn.style.opacity = '0.5';
            dappTriggerBtn.style.pointerEvents = 'none';
        }
        
        // Block navigation tabs
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.style.opacity = '0.5';
            link.style.pointerEvents = 'none';
        });
    }

    updateWalletUI(address, balance, networkName = null, isGanache = true) {
        if (address) {
            this.connectWalletBtn.classList.add('connected');
            this.connectWalletText.textContent = 'Disconnect';
            this.walletInfoDisplay.style.display = 'flex';
            this.walletStatusText.textContent = 'Connected';
            this.walletStatusText.className = 'wallet-status connected';
            const truncated = address.substring(0, 6) + '...' + address.substring(address.length - 4);
            this.walletAddressText.textContent = truncated;
            this.walletAddressText.title = address;
            
            if (balance === 'Error' || !balance) {
                this.walletBalanceText.className = 'wallet-bal error';
                this.walletBalanceText.textContent = 'Error';
                if (!this.fallbackBalance) {
                    this.fallbackBalance = (10 + Math.random() * 90).toFixed(4);
                }
                balance = this.fallbackBalance;
            } else {
                this.walletBalanceText.className = 'wallet-bal';
                this.walletBalanceText.textContent = `${balance} ETH`;
            }

            if (this.walletNetworkText && networkName) {
                this.walletNetworkText.textContent = networkName;
                this.walletNetworkText.style.color = isGanache ? '#10b981' : '#f43f5e';
            }

            // Update dedicated wallet monitor panel
            if (this.monitorAddress) this.monitorAddress.textContent = address;
            if (this.monitorBalance) this.monitorBalance.textContent = `${balance} ETH`;
            if (this.monitorNetBadge) {
                this.monitorNetBadge.textContent = networkName || 'Connected';
                this.monitorNetBadge.className = isGanache ? 'wallet-monitor-badge online' : 'wallet-monitor-badge offline';
            }
        } else {
            this.connectWalletBtn.classList.remove('connected');
            this.connectWalletText.textContent = 'Connect Wallet';
            this.walletInfoDisplay.style.display = 'none';
            this.walletStatusText.textContent = 'Disconnected';
            this.walletStatusText.className = 'wallet-status disconnected';
            this.walletAddressText.textContent = '0x...';
            this.walletBalanceText.textContent = '0.00 ETH';
            if (this.walletNetworkText) {
                this.walletNetworkText.textContent = 'Unknown Network';
            }
            if (this.networkAlertBar) {
                this.networkAlertBar.style.display = 'none';
            }

            // Reset dedicated wallet monitor panel
            if (this.monitorAddress) this.monitorAddress.textContent = victimWallet;
            if (this.monitorBalance) {
                if (!this.fallbackBalance) {
                    this.fallbackBalance = (10 + Math.random() * 90).toFixed(4);
                }
                this.monitorBalance.textContent = `${this.fallbackBalance} ETH`;
            }
            if (this.monitorNetBadge) {
                this.monitorNetBadge.textContent = 'Offline';
                this.monitorNetBadge.className = 'wallet-monitor-badge offline';
            }
            if (this.monitorBlock) this.monitorBlock.textContent = '#0';
        }
    }

    disconnectWallet() {
        console.log('User requested wallet disconnect.');
        this.currentWalletAddress = null;
        if (this.blockListenerProvider) {
            try {
                this.blockListenerProvider.removeAllListeners("block");
            } catch (e) {
                console.error("Error removing block listeners on disconnect:", e);
            }
            this.blockListenerProvider = null;
        }
        this.updateWalletUI(null, null);
        alert('Disconnected from BlockShield. (To fully revoke permissions, manage connections in your MetaMask extension)');
    }

    async fetchThreats() {
        try {
            const response = await fetch('/api/v1/threats', {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });

            if (!response.ok) {
                if (response.status === 401) {
                    this.handleAuthExpiration();
                    return;
                }
                throw new Error('Failed to download threat registry logs.');
            }

            const threats = await response.json();
            this.renderThreatsTable(threats);
        } catch (err) {
            console.error('Threat registry fetch failure:', err);
        }
    }

    renderThreatsTable(threats) {
        const tbody = document.getElementById('threatsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        if (threats.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No registered threats.</td></tr>';
            return;
        }

        threats.forEach(t => {
            const row = document.createElement('tr');
            const dateStr = new Date(t.added_at).toLocaleString();
            
            let label = '';
            if (t.entity_type === 'wallet') label = 'Wallet Address';
            else if (t.entity_type === 'contract') label = 'Smart Contract';
            else label = 'Phishing Domain';

            let classBadge = 'Medium';
            if (t.severity === 'Critical') classBadge = 'Critical';
            else if (t.severity === 'High Risk') classBadge = 'High';

            row.innerHTML = `
                <td><span style="font-weight: 500; color: var(--neon-aqua);">${label}</span></td>
                <td><code style="color: var(--text-secondary); font-family: monospace; font-size: 0.85rem; word-break: break-all;">${t.value}</code></td>
                <td><span class="threat-badge ${classBadge}">${t.severity}</span></td>
                <td><span style="color: var(--text-secondary);">${t.description}</span></td>
                <td><span style="color: var(--text-dim); font-size: 0.75rem;">${dateStr}</span></td>
            `;
            tbody.appendChild(row);
        });
    }

    handleAuthExpiration() {
        localStorage.removeItem('access_token');
        this.token = null;
        this.showAuthPortal();
    }

    async fetchLogs() {
        try {
            const response = await fetch('/api/transactions?limit=80', {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            if (!response.ok) {
                if (response.status === 401) {
                    this.handleAuthExpiration();
                    return;
                }
                throw new Error('Failed to load transaction logs');
            }
            
            this.allLogs = await response.json();
            
            // Calculate stats
            this.calculateMetrics();
            
            // Render logs table
            this.renderLogs();
            
            // Seed chart data
            if (this.allLogs.length > 0) {
                const recentScores = this.allLogs.slice(0, 50).reverse().map(log => {
                    return Math.min(100, Math.max(5, (log.anomaly_score + 0.3) * 150));
                });
                // Pad to 50 if necessary
                while (recentScores.length < 50) {
                    recentScores.unshift(10 + Math.random()*15);
                }
                this.chartData = recentScores;
            }
            
        } catch (err) {
            console.error('Fetch logs error:', err);
        }
    }

    getBadgeClass(sev) {
        if (sev === 'Critical' || sev === 'HIGH') return 'critical';
        if (sev === 'High Risk' || sev === 'MEDIUM') return 'high';
        if (sev === 'Medium Risk' || sev === 'LOW') return 'medium';
        return 'low'; // Low Risk or NONE
    }

    calculateMetrics() {
        const total = this.allLogs.length;
        const anomalies = this.allLogs.filter(log => log.severity !== 'Low Risk' && log.severity !== 'NONE');
        
        // Count blocked transactions based on mempool_status = "blocked"
        const blocked = this.allLogs.filter(log => log.mempool_status === 'blocked').length;
        
        const critAnomalies = this.allLogs.filter(log => log.severity === 'Critical' || log.severity === 'HIGH');
        const highAnomalies = this.allLogs.filter(log => log.severity === 'High Risk' || log.severity === 'MEDIUM');
        const medAnomalies = this.allLogs.filter(log => log.severity === 'Medium Risk' || log.severity === 'LOW');
        const normalLogs = this.allLogs.filter(log => log.severity === 'Low Risk' || log.severity === 'NONE');
        
        // Set metrics counts
        this.threatsDetectedEl.textContent = anomalies.length.toLocaleString();
        this.blockedAttacksEl.textContent = blocked.toLocaleString();
        this.activeNodesEl.textContent = total.toLocaleString();
        
        const rate = total > 0 ? ((anomalies.length / total) * 100).toFixed(1) : '0.0';
        this.intrusionRateEl.textContent = `${rate}% intrusion rate`;
        
        const blockRate = anomalies.length > 0 ? ((blocked / anomalies.length) * 100).toFixed(1) : '0.0';
        this.highAlertPercentageEl.textContent = `${blockRate}% of anomalies blocked`;
        
        // Progress counts labels
        this.highScoreCountEl.textContent = `${critAnomalies.length} Logs`;
        this.medScoreCountEl.textContent = `${highAnomalies.length} Logs`;
        this.lowScoreCountEl.textContent = `${medAnomalies.length} Logs`;
        this.noneScoreCountEl.textContent = `${normalLogs.length} Logs`;
        
        // Progress Bars fill
        const setWidth = (el, count) => {
            const pct = total > 0 ? (count / total) * 100 : 0;
            el.style.width = `${pct}%`;
        };
        setWidth(this.highScoreProgress, critAnomalies.length);
        setWidth(this.medScoreProgress, highAnomalies.length);
        setWidth(this.lowScoreProgress, medAnomalies.length);
        setWidth(this.noneScoreProgress, normalLogs.length);
        
        // Anomaly stats
        if (total > 0) {
            const sumScore = this.allLogs.reduce((acc, log) => acc + log.anomaly_score, 0);
            this.avgAnomalyScoreEl.textContent = (sumScore / total).toFixed(4);
            
            const maxScore = Math.max(...this.allLogs.map(log => log.anomaly_score));
            this.peakAnomalyScoreEl.textContent = maxScore.toFixed(4);
            
            const sumGas = this.allLogs.reduce((acc, log) => acc + (log.gas_used || 21000), 0);
            this.avgGasUsedEl.textContent = Math.floor(sumGas / total).toLocaleString();
        } else {
            this.avgAnomalyScoreEl.textContent = '0.0000';
            this.peakAnomalyScoreEl.textContent = '0.0000';
            this.avgGasUsedEl.textContent = '21,000';
        }
        
        // Fill right alerts list
        this.populateSecurityAlerts(anomalies.slice(0, 10));
    }

    renderLogs() {
        this.threatList.innerHTML = '';
        
        if (this.filterMode === 'anomalies') {
            this.filteredLogs = this.allLogs.filter(log => log.severity !== 'Low Risk' && log.severity !== 'NONE');
        } else {
            this.filteredLogs = this.allLogs;
        }
        
        if (this.filteredLogs.length === 0) {
            this.threatList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-dim);">No transactions found in this view. Use Simulator or generate mock traffic.</div>';
            return;
        }
        
        this.filteredLogs.forEach((log) => {
            const item = document.createElement('div');
            item.className = 'threat-item';
            
            const truncateTx = (h) => h ? `${h.substring(0, 10)}...${h.substring(h.length - 8)}` : 'N/A';
            const cleanTime = (d) => {
                const date = new Date(d);
                return date.toLocaleTimeString();
            };
            
            const isAnomaly = log.severity !== 'Low Risk' && log.severity !== 'NONE';
            const badgeClass = this.getBadgeClass(log.severity);
            
            // Format status badge
            let statusBadge = '';
            if (log.mempool_status === 'blocked') {
                statusBadge = `<span class="threat-badge critical" style="margin-left: 8px;">Blocked</span>`;
            } else if (log.mempool_status === 'pending') {
                statusBadge = `<span class="threat-badge medium" style="margin-left: 8px;">Pending</span>`;
            } else {
                statusBadge = `<span class="threat-badge low" style="margin-left: 8px;">Confirmed</span>`;
            }

            item.innerHTML = `
                <div class="threat-severity ${badgeClass}"></div>
                <div class="threat-info">
                    <div class="threat-title">${isAnomaly ? log.severity + ' Anomaly Detected' : 'Normal Transaction'}</div>
                    <div class="threat-description">Tx: ${truncateTx(log.tx_hash)} | Score: ${log.anomaly_score.toFixed(4)}</div>
                </div>
                <div class="threat-meta">
                    <span class="threat-time">${cleanTime(log.timestamp)}</span>
                    <span class="threat-badge ${badgeClass}">${log.severity}</span>
                    ${statusBadge}
                </div>
            `;
            
            item.addEventListener('click', () => {
                this.openInspectModal(log);
            });
            
            this.threatList.appendChild(item);
        });
    }

    populateSecurityAlerts(anomalies) {
        this.alertsList.innerHTML = '';
        
        const highAlerts = anomalies.filter(l => l.severity === 'Critical' || l.severity === 'HIGH' || l.severity === 'High Risk' || l.severity === 'MEDIUM');
        this.alertCountBadge.textContent = highAlerts.length;
        this.alertCountText.textContent = `${highAlerts.length} Active`;
        
        if (highAlerts.length === 0) {
            this.alertsList.innerHTML = '<div style="padding: 1.5rem; text-align: center; color: var(--text-dim); font-size: 0.85rem;">No critical/high threats recorded.</div>';
            return;
        }
        
        highAlerts.forEach((alert) => {
            const item = document.createElement('div');
            const mappedBadge = this.getBadgeClass(alert.severity);
            item.className = `alert-item ${mappedBadge}`;
            
            const cleanTime = (d) => {
                const date = new Date(d);
                return date.toLocaleTimeString();
            };
            
            item.innerHTML = `
                <div class="alert-header">
                    <div class="alert-title">${alert.severity} Risk Anomaly</div>
                    <div class="alert-time">${cleanTime(alert.timestamp)}</div>
                </div>
                <div class="alert-message">Tx: ${alert.tx_hash}<br>Gas used: ${alert.gas_used.toLocaleString()} | Value: ${alert.value_eth.toFixed(4)} ETH</div>
            `;
            
            this.alertsList.appendChild(item);
        });
    }

    openInspectModal(log) {
        this.modalTxHash.textContent = log.tx_hash || 'N/A';
        this.modalFrom.textContent = log.from_address || '0x0000000000000000000000000000000000000000';
        this.modalTo.textContent = log.to_address || '0x0000000000000000000000000000000000000000';
        this.modalAnomalyScore.textContent = log.anomaly_score.toFixed(6);
        this.modalSeverity.textContent = log.severity;
        this.modalGas.textContent = log.gas_used ? log.gas_used.toLocaleString() : '21,000';
        this.modalValue.textContent = log.value_eth ? `${log.value_eth.toFixed(6)} ETH` : '0.000000 ETH';
        
        const badgeClass = this.getBadgeClass(log.severity);
        this.modalSeverity.className = `detail-value threat-badge ${badgeClass}`;
        
        this.detailsModal.classList.add('active');
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
        
        console.log(`Connecting to WebSocket at ${wsUrl}`);
        this.ws = new WebSocket(wsUrl);
        
        const statusPulse = document.getElementById('statusPulse');
        const statusText = document.getElementById('statusText');
        
        this.ws.onopen = () => {
            statusText.textContent = "MONITORING";
            statusPulse.style.background = "var(--neon-aqua)";
            statusPulse.style.boxShadow = "0 0 10px var(--neon-aqua)";
            console.log("WebSocket connected.");
        };
        
        this.ws.onclose = () => {
            statusText.textContent = "OFFLINE";
            statusPulse.style.background = "var(--rose-pink)";
            statusPulse.style.boxShadow = "0 0 10px var(--rose-pink)";
            // Retry connection in 5 seconds
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        
        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                
                if (message.type === 'TRANSACTION') {
                    // Prepend new transaction log to database array
                    const newTxLog = {
                        id: message.id,
                        tx_hash: message.tx_hash,
                        gas_used: message.gas_used,
                        gas_fee_eth: message.gas_fee_eth,
                        value_eth: message.value_eth,
                        from_address: message.from_address,
                        to_address: message.to_address,
                        anomaly_score: message.anomaly_score,
                        severity: message.severity,
                        mempool_status: message.mempool_status || 'confirmed',
                        timestamp: new Date().toISOString()
                    };
                    this.allLogs.unshift(newTxLog);
                    
                    // Recalculate metrics
                    this.calculateMetrics();
                    
                    // Re-render logs table
                    this.renderLogs();
                    
                    // Push score to graph list
                    const displayValue = Math.min(100, Math.max(5, (message.anomaly_score + 0.3) * 150));
                    this.chartData.shift();
                    this.chartData.push(displayValue);

                    // TRIGGER POPUP FOR DETECTED TRANSACTION
                    // Check if it's from our blocked attacker
                    const isFlagged = flaggedWallets.some(addr => addr.toLowerCase() === message.from_address.toLowerCase());
                    const isFromMe = message.from_address && this.currentWalletAddress && message.from_address.toLowerCase() === this.currentWalletAddress.toLowerCase();
                    const isToMe = message.to_address && this.currentWalletAddress && message.to_address.toLowerCase() === this.currentWalletAddress.toLowerCase();
                    const isToVictim = message.to_address && message.to_address.toLowerCase() === victimWallet.toLowerCase();
                    const isToGanache = message.to_address && this.ganacheAccounts && this.ganacheAccounts.some(a => a.toLowerCase() === message.to_address.toLowerCase());
                    const isGanacheTx = isFromMe || isToMe || isToVictim || isToGanache;
                    
                    if (isGanacheTx && !this.notifiedTxHashes.has(message.tx_hash)) {
                        this.notifiedTxHashes.add(message.tx_hash);
                        const amountStr = parseFloat(message.value_eth).toFixed(4);
                        const timeStr = new Date().toLocaleString();
                        
                        if (isFlagged) {
                            console.warn(`%c⚠️ [SUSPICIOUS WALLET ACTIVITY] WebSocket alert: ${message.from_address}`, 'color: #eab308; font-weight: bold;');
                            console.error(`%c🚫 [TRANSACTION BLOCKED] WebSocket blocked trace!`, 'color: #f43f5e; font-weight: bold;');
                            
                            // Visual blocked alert
                            const fakeTxObj = { from: message.from_address, value: ethers.parseEther(message.value_eth.toString()) };
                            this.showSecurityAlertPopup(fakeTxObj, amountStr, timeStr);
                        } else {
                            console.log(`%c📥 [INCOMING TRANSACTION] WebSocket alert: Hash: ${message.tx_hash}`, 'color: #00ffff; font-weight: bold;');
                            this.showIncomingTxNotification(newTxLog, amountStr, timeStr);
                        }
                    }
                } else if (message.type === 'ALERT') {
                    // Flash screen header or status indicator
                    statusText.textContent = "ALERT DETECTED";
                    statusPulse.style.background = "var(--rose-pink)";
                    statusPulse.style.boxShadow = "0 0 15px var(--rose-pink)";
                    
                    // Reset status in 3s
                    setTimeout(() => {
                        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                            statusText.textContent = "MONITORING";
                            statusPulse.style.background = "var(--neon-aqua)";
                            statusPulse.style.boxShadow = "0 0 10px var(--neon-aqua)";
                        }
                    }, 3000);
                } else if (message.type === 'TRANSACTION_UPDATE') {
                    // Update mempool status of specific log
                    const logIndex = this.allLogs.findIndex(log => log.id === message.id || log.tx_hash === message.tx_hash);
                    if (logIndex !== -1) {
                        this.allLogs[logIndex].mempool_status = message.mempool_status;
                        this.calculateMetrics();
                        this.renderLogs();
                    }
                }
            } catch (err) {
                console.error("Error parsing WS message:", err);
            }
        };
    }

    startCanvasChartAnimation() {
        const canvas = this.chartCanvas;
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        const resizeCanvas = () => {
            canvas.width = canvas.parentElement.offsetWidth;
            canvas.height = canvas.parentElement.offsetHeight;
        };
        
        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);
        
        const dataPoints = 50;
        
        const drawChart = () => {
            if (!this.chartCanvas) return;
            
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            const padding = 20;
            const width = canvas.width - padding * 2;
            const height = canvas.height - padding * 2;
            const step = width / (dataPoints - 1);
            
            // Draw baseline grid lines
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
                const y = padding + (height / 4) * i;
                ctx.beginPath();
                ctx.moveTo(padding, y);
                ctx.lineTo(canvas.width - padding, y);
                ctx.stroke();
            }
            
            // Create line gradients
            const gradient = ctx.createLinearGradient(0, 0, canvas.width, 0);
            gradient.addColorStop(0, 'rgba(0, 255, 255, 0.8)');
            gradient.addColorStop(0.5, 'rgba(147, 51, 234, 0.8)');
            gradient.addColorStop(1, 'rgba(255, 105, 180, 0.8)');
            
            // Draw area fill
            ctx.beginPath();
            ctx.moveTo(padding, canvas.height - padding);
            
            this.chartData.forEach((value, i) => {
                const x = padding + i * step;
                const y = canvas.height - padding - (value / 100) * height;
                ctx.lineTo(x, y);
            });
            
            ctx.lineTo(canvas.width - padding, canvas.height - padding);
            ctx.closePath();
            
            const fillGradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
            fillGradient.addColorStop(0, 'rgba(0, 255, 255, 0.15)');
            fillGradient.addColorStop(1, 'rgba(0, 255, 255, 0)');
            ctx.fillStyle = fillGradient;
            ctx.fill();
            
            // Draw line
            ctx.beginPath();
            this.chartData.forEach((value, i) => {
                const x = padding + i * step;
                const y = canvas.height - padding - (value / 100) * height;
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            
            ctx.strokeStyle = gradient;
            ctx.lineWidth = 2.5;
            ctx.stroke();
            
            // Add subtle noise to pulse graph
            if (Math.random() < 0.1) {
                const lastVal = this.chartData[this.chartData.length - 1];
                const noise = (Math.random() - 0.5) * 2;
                this.chartData[this.chartData.length - 1] = Math.min(100, Math.max(5, lastVal + noise));
            }
            
            requestAnimationFrame(drawChart);
        };
        
        drawChart();
    }
}

// Instantiate App on Page Load
document.addEventListener('DOMContentLoaded', () => {
    window.blockShieldApp = new BlockShieldApp();
    console.log('%c🔐 BlockShield IPS Activated', 'color: #00ffff; font-size: 16px; font-weight: bold;');
});
