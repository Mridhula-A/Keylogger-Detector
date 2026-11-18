
// ==========================================
// KEYGUARD SECURITY CENTER
// MAIN JAVASCRIPT
// ==========================================


// ==========================================
// SCANNER API ENDPOINTS
// ==========================================

const scannerEndpoints = {
    process: "/api/scan",
    keyboard: "/api/keyboard-scan",
    startup: "/api/startup-scan",
    registry: "/api/registry-scan",
    file: "/api/file-scan"
};


// ==========================================
// SCAN HISTORY STORAGE
// ==========================================

let scanHistoryRecords = [];


// ==========================================
// RUN SCANNER
// ==========================================

async function runScanner(scannerName) {

    const container = document.getElementById("results-container");
    const status = document.getElementById("scan-status");
    const endpoint = scannerEndpoints[scannerName];

    if (!endpoint || !container || !status) return;

    status.textContent = "SCANNING...";
    status.style.color = "#39ff88";

    container.innerHTML = `
        <div class="empty-state">
            <h3>Security scan in progress...</h3>
            <p>Please wait while KeyGuard analyzes your system.</p>
        </div>
    `;

    try {

        const response = await fetch(endpoint);
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Scanner failed.");
        }

        status.textContent = "SCAN COMPLETED";
        status.style.color = "#39ff88";

        displayResults(result);

        await loadScanHistory();
        await loadDashboardStatistics();

    } catch (error) {

        status.textContent = "SCAN FAILED";
        status.style.color = "#ff4d6d";

        container.innerHTML = `
            <div class="empty-state">
                <h3>Scan Error</h3>
                <p>${escapeHTML(error.message)}</p>
            </div>
        `;

        console.error(error);
    }
}


// ==========================================
// IDENTIFY SCANNER
// ==========================================

function getScannerName(title) {

    const names = {
        "Process Scanner": "process",
        "Keyboard API Indicator Scanner": "keyboard",
        "Windows Startup Scanner": "startup",
        "Registry Security Scanner": "registry",
        "Suspicious File Scanner": "file"
    };

    return names[title] || "unknown";
}


// ==========================================
// GET SCANNER STATISTICS
// ==========================================

function getScannerStatistics(data, scannerName) {

    const total = Number(
        data.total_processes ??
        data.total_scanned ??
        data.files_scanned ??
        data.total_entries ??
        0
    );

    const suspicious = Number(
        data.suspicious_processes ??
        data.suspicious_entries ??
        data.suspicious_files ??
        data.indicator_count ??
        0
    );

    let safe = null;

    if (scannerName !== "keyboard") {

        safe = Number(
            data.safe_processes ??
            data.safe_entries ??
            data.safe_files ??
            Math.max(0, total - suspicious)
        );
    }

    return { total, suspicious, safe };
}


// ==========================================
// DATABASE-BACKED DASHBOARD STATISTICS
// ==========================================

async function loadDashboardStatistics() {

    try {

        const response = await fetch("/api/dashboard-stats");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Unable to load dashboard statistics."
            );
        }

        const stats = result.statistics;

        const totalScansElement =
            document.getElementById("total-scans");

        const totalItemsElement =
            document.getElementById("total-items");

        const suspiciousElement =
            document.getElementById("total-suspicious");

        if (totalScansElement) {
            totalScansElement.textContent =
                Number(stats.total_scans || 0);
        }

        if (totalItemsElement) {
            totalItemsElement.textContent =
                Number(stats.total_items || 0);
        }

        if (suspiciousElement) {
            suspiciousElement.textContent =
                Number(stats.suspicious_items || 0);
        }

    } catch (error) {

        console.error("Dashboard statistics error:", error);

    }
}


// ==========================================
// UPDATE LAST SCAN INFORMATION
// ==========================================

function updateLastScanInformation(scannerName) {

    const lastStatusElement =
        document.getElementById("last-scan-status");

    const lastNameElement =
        document.getElementById("last-scan-name");

    if (lastStatusElement) {
        lastStatusElement.textContent = "COMPLETED";
    }

    if (lastNameElement) {
        lastNameElement.textContent = scannerName.toUpperCase();
    }
}


// ==========================================
// SECURITY STATUS
// ==========================================

function calculateSecurityStatus(count) {

    if (count >= 3) {
        return {
            status: "CRITICAL",
            color: "#ff4d6d",
            message: "Multiple indicators require investigation."
        };
    }

    if (count > 0) {
        return {
            status: "WARNING",
            color: "#ffc857",
            message: "Suspicious indicators require further investigation."
        };
    }

    return {
        status: "SAFE",
        color: "#39ff88",
        message: "No suspicious indicators reported."
    };
}


// ==========================================
// DISPLAY SCAN RESULTS
// ==========================================

function displayResults(result) {

    const container = document.getElementById("results-container");

    if (!container) return;

    const data = result.data || {};
    const scannerName = getScannerName(result.scanner);
    const stats = getScannerStatistics(data, scannerName);
    const security = calculateSecurityStatus(stats.suspicious);

    updateLastScanInformation(scannerName);

    let html = `

        <div class="scan-summary">
            <h3>${escapeHTML(result.scanner)}</h3>
            <p>
                <span class="green-text">✓</span>
                Scan completed successfully
            </p>
        </div>

        <div class="security-status-card">
            <p class="status-heading">SECURITY STATUS</p>
            <h2 style="color:${security.color}">
                ${security.status}
            </h2>
            <p>${escapeHTML(security.message)}</p>
        </div>

        <div class="scanner-statistics">

            <div class="stat-box">
                <span class="stat-icon">⌕</span>
                <h2>${stats.total}</h2>
                <p>Items Scanned</p>
            </div>

            <div class="stat-box">
                <span class="stat-icon">✓</span>
                <h2>${stats.safe === null ? "N/A" : stats.safe}</h2>
                <p>Safe Items</p>
            </div>

            <div class="stat-box">
                <span class="stat-icon">!</span>
                <h2>${stats.suspicious}</h2>
                <p>Suspicious Indicators</p>
            </div>

        </div>
    `;

    const items = Array.isArray(data.results) ? data.results : [];

    if (scannerName === "keyboard") {

        html += tableHTML(
            "Keyboard API Detection Results",
            ["PID", "Process", "Detected APIs", "Risk"],
            items,
            item => `
                <td>${escapeHTML(item.pid)}</td>
                <td>${escapeHTML(item.process)}</td>
                <td>
                    ${Array.isArray(item.detected_apis)
                        ? item.detected_apis.map(escapeHTML).join("<br>")
                        : "None"}
                </td>
                <td>${riskBadge(item.risk)}</td>
            `,
            4
        );

    } else if (scannerName === "startup") {

        html += tableHTML(
            "Windows Startup Entries",
            ["Name", "Command / Path", "Source", "Indicators", "Risk"],
            items,
            item => `
                <td>${escapeHTML(item.name)}</td>
                <td class="path-cell">
                    ${escapeHTML(item.command ?? item.path)}
                </td>
                <td>${escapeHTML(item.source)}</td>
                <td>${formatIndicators(item.indicators)}</td>
                <td>${riskBadge(item.risk)}</td>
            `,
            5
        );

    } else if (scannerName === "registry") {

        html += tableHTML(
            "Registry Security Analysis",
            ["Value Name", "Current Value / Command", "Source", "Indicators", "Risk"],
            items,
            item => `
                <td>
                    <strong>${escapeHTML(item.name)}</strong>
                </td>
                <td class="registry-value">
                    ${escapeHTML(item.command ?? item.value)}
                </td>
                <td>${escapeHTML(item.source)}</td>
                <td>${formatIndicators(item.indicators)}</td>
                <td>${riskBadge(item.risk)}</td>
            `,
            5
        );

    } else if (scannerName === "file") {

        html += tableHTML(
            "Suspicious File Analysis",
            ["File Name", "Extension", "Size", "Modified", "SHA-256", "Indicators", "Risk"],
            items,
            item => `
                <td><strong>${escapeHTML(item.name)}</strong></td>
                <td>${escapeHTML(item.extension)}</td>
                <td>${formatBytes(item.size_bytes)}</td>
                <td>${escapeHTML(item.modified)}</td>
                <td class="hash-cell">${escapeHTML(item.sha256)}</td>
                <td>${formatIndicators(item.indicators)}</td>
                <td>${riskBadge(item.risk)}</td>
            `,
            7
        );

        html += `
            <p class="table-note">
                Scan directory: ${escapeHTML(data.scan_directory)}
            </p>
        `;

    } else if (scannerName === "process") {

        html += tableHTML(
            "Running Process Analysis",
            ["PID", "Process", "Executable Path", "User", "Status", "Risk", "Indicators"],
            data.processes || [],
            item => `
                <td>${escapeHTML(item.pid)}</td>
                <td>${escapeHTML(item.name)}</td>
                <td class="path-cell">${escapeHTML(item.exe)}</td>
                <td>${escapeHTML(item.username)}</td>
                <td>${escapeHTML(item.status)}</td>
                <td>${riskBadge(item.risk)}</td>
                <td>${formatIndicators(item.indicators)}</td>
            `,
            7
        );

    } else {

        html += `
            <div class="result-details">
                <h4>Complete Scan Information</h4>
                <pre>${escapeHTML(JSON.stringify(data, null, 4))}</pre>
            </div>
        `;
    }

    container.innerHTML = html;
}


// ==========================================
// REUSABLE TABLE BUILDER
// ==========================================

function tableHTML(title, headers, items, rowTemplate, columnCount) {

    return `

        <div class="result-details">

            <h4>${escapeHTML(title)}</h4>

            <div class="table-container">

                <table class="scanner-table">

                    <thead>
                        <tr>
                            ${headers.map(header =>
                                `<th>${escapeHTML(header)}</th>`
                            ).join("")}
                        </tr>
                    </thead>

                    <tbody>

                        ${items.length
                            ? items.map(item =>
                                `<tr>${rowTemplate(item)}</tr>`
                            ).join("")
                            : `
                                <tr>
                                    <td colspan="${columnCount}" class="no-results">
                                        No matching entries found.
                                    </td>
                                </tr>
                            `
                        }

                    </tbody>

                </table>

            </div>

        </div>
    `;
}


// ==========================================
// RISK BADGE
// ==========================================

function riskBadge(risk) {

    const value = String(risk ?? "Unknown");

    let css = "risk-neutral";

    if (
        value === "Needs Investigation" ||
        value === "Medium"
    ) {
        css = "risk-warning";

    } else if (
        value === "High" ||
        value === "Scan Incomplete"
    ) {
        css = "risk-danger";

    } else if (
        value === "Low" ||
        value === "No Obvious Indicator" ||
        value === "COMPLETED"
    ) {
        css = "risk-safe";
    }

    return `
        <span class="${css}">
            ${escapeHTML(value)}
        </span>
    `;
}


// ==========================================
// FORMAT INDICATORS
// ==========================================

function formatIndicators(indicators) {

    if (!Array.isArray(indicators) || indicators.length === 0) {
        return '<span class="no-indicator">None reported</span>';
    }

    return indicators.map(item =>
        `<div class="indicator-item">${escapeHTML(item)}</div>`
    ).join("");
}


// ==========================================
// FILE SIZE FORMATTER
// ==========================================

function formatBytes(bytes) {

    const size = Number(bytes);

    if (!Number.isFinite(size) || size < 0) return "N/A";

    if (size < 1024) return size + " B";

    if (size < 1048576) {
        return (size / 1024).toFixed(2) + " KB";
    }

    return (size / 1048576).toFixed(2) + " MB";
}


// ==========================================
// SCAN HISTORY - LOAD FROM DATABASE
// ==========================================

async function loadScanHistory() {

    const container = document.getElementById("scan-history-container");
    const status = document.getElementById("history-status");

    if (!container) return;

    if (status) {
        status.textContent = "LOADING HISTORY...";
    }

    container.innerHTML = `
        <div class="empty-state">
            <p>Loading scan history...</p>
        </div>
    `;

    try {

        const response = await fetch("/api/history");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to load scan history.");
        }

        const history = Array.isArray(result.history)
            ? result.history
            : [];

        displayScanHistory(history);

        if (status) {
            status.textContent = history.length
                ? `${history.length} RECORDS FOUND`
                : "NO RECORDS FOUND";
        }

    } catch (error) {

        container.innerHTML = `
            <div class="empty-state">
                <h3>History unavailable</h3>
                <p>${escapeHTML(error.message)}</p>
            </div>
        `;

        if (status) {
            status.textContent = "HISTORY UNAVAILABLE";
        }

        console.error("Scan history error:", error);
    }
}


// ==========================================
// DISPLAY SCAN HISTORY
// ==========================================

function displayScanHistory(history) {

    scanHistoryRecords = Array.isArray(history) ? history : [];

    filterScanHistory();
}


// ==========================================
// SEARCH AND FILTER SCAN HISTORY
// ==========================================

function filterScanHistory() {

    const searchInput = document.getElementById("history-search");
    const scannerFilter = document.getElementById("history-scanner-filter");
    const statusFilter = document.getElementById("history-status-filter");

    const searchValue = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    const selectedScanner = scannerFilter
        ? scannerFilter.value
        : "all";

    const selectedStatus = statusFilter
        ? statusFilter.value
        : "all";

    const filteredHistory = scanHistoryRecords.filter(scan => {

        const scanId = String(scan.id ?? "").toLowerCase();
        const scannerName = String(scan.scanner_name ?? "").toLowerCase();
        const scanStatus = String(scan.scan_status ?? "").toUpperCase();

        const matchesSearch =
            scanId.includes(searchValue) ||
            scannerName.includes(searchValue);

        const matchesScanner =
            selectedScanner === "all" ||
            scan.scanner_name === selectedScanner;

        const matchesStatus =
            selectedStatus === "all" ||
            scanStatus === selectedStatus.toUpperCase();

        return matchesSearch && matchesScanner && matchesStatus;
    });

    renderFilteredScanHistory(filteredHistory);
}


// ==========================================
// RENDER FILTERED SCAN HISTORY
// ==========================================

function renderFilteredScanHistory(history) {

    const container = document.getElementById("scan-history-container");
    const status = document.getElementById("history-status");

    if (!container) return;

    if (!history.length) {

        container.innerHTML = `
            <div class="empty-state">
                <h3>No Matching Scan Records</h3>
                <p>Try changing your search or filter selection.</p>
            </div>
        `;

        if (status) {
            status.textContent = "0 MATCHING RECORDS";
        }

        return;
    }

    let html = `

        <div class="table-container">

            <table class="scanner-table">

                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Scanner</th>
                        <th>Status</th>
                        <th>Items Scanned</th>
                        <th>Suspicious</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>

                <tbody>
    `;

    history.forEach(scan => {

        const date = scan.scan_date
            ? new Date(
                scan.scan_date.replace(" ", "T") + "Z"
              ).toLocaleString()
            : "N/A";

        const scanId = Number(scan.id);

        html += `
            <tr>

                <td>${escapeHTML(scan.id)}</td>

                <td>
                    <strong>${escapeHTML(scan.scanner_name)}</strong>
                </td>

                <td>
                    ${riskBadge(scan.scan_status)}
                </td>

                <td>${escapeHTML(scan.total_items)}</td>

                <td>${escapeHTML(scan.suspicious_count)}</td>

                <td>${escapeHTML(date)}</td>

                <td>

                    <button
                        class="history-action-btn"
                        onclick="viewScanReport(${scanId})">
                        VIEW
                    </button>

                    <button
                        class="history-action-btn"
                        onclick="downloadScanReport(${scanId})">
                        DOWNLOAD
                    </button>

                    <button
                        class="history-action-btn"
                        onclick="deleteScanHistory(${scanId})">
                        DELETE
                    </button>

                </td>

            </tr>
        `;
    });

    html += `
                </tbody>
            </table>

        </div>
    `;

    container.innerHTML = html;

    if (status) {
        status.textContent =
            `${history.length} MATCHING RECORDS`;
    }
}


// ==========================================
// REFRESH SCAN HISTORY
// ==========================================

function refreshScanHistory() {
    loadScanHistory();
}


// ==========================================
// DELETE INDIVIDUAL SCAN HISTORY
// ==========================================

async function deleteScanHistory(scanId) {

    if (!confirm(`Delete scan record #${scanId}?`)) return;

    try {

        const response = await fetch(`/api/history/${scanId}`, {
            method: "DELETE"
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to delete scan history.");
        }

        await loadScanHistory();
        await loadDashboardStatistics();

    } catch (error) {

        alert(error.message);
        console.error("Delete history error:", error);
    }
}


// ==========================================
// CLEAR ALL SCAN HISTORY
// ==========================================

async function clearAllScanHistory() {

    if (!confirm("Delete ALL scan history? This cannot be undone.")) return;

    try {

        const response = await fetch("/api/history/clear", {
            method: "DELETE"
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to clear scan history.");
        }

        await loadScanHistory();
        await loadDashboardStatistics();

    } catch (error) {

        alert(error.message);
        console.error("Clear history error:", error);
    }
}


// ==========================================
// VIEW COMPLETE SCAN REPORT - MODAL
// ==========================================

async function viewScanReport(scanId) {

    try {

        const response = await fetch("/api/history");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to retrieve scan report.");
        }

        const scan = result.history.find(
            item => Number(item.id) === Number(scanId)
        );

        if (!scan) {
            throw new Error("Scan report not found.");
        }

        let report;

        try {
            report = JSON.parse(scan.report_json || "{}");
        } catch {
            throw new Error("The saved scan report contains invalid JSON.");
        }

        const modal = document.getElementById("report-modal");
        const title = document.getElementById("report-modal-title");
        const content = document.getElementById("report-modal-content");

        if (!modal || !title || !content) {
            throw new Error("Report modal elements are missing from index.html.");
        }

        title.textContent =
            `${scan.scanner_name} - Report #${scan.id}`;

        content.textContent = JSON.stringify(report, null, 4);

        modal.hidden = false;

    } catch (error) {

        alert(error.message);
        console.error("View report error:", error);
    }
}


// ==========================================
// CLOSE REPORT MODAL
// ==========================================

function closeScanReport() {

    const modal = document.getElementById("report-modal");

    if (modal) {
        modal.hidden = true;
    }
}


// ==========================================
// DOWNLOAD SCAN REPORT
// ==========================================

async function downloadScanReport(scanId) {

    let url = null;

    try {

        const response = await fetch("/api/history");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Unable to download scan report.");
        }

        const scan = result.history.find(
            item => Number(item.id) === Number(scanId)
        );

        if (!scan) {
            throw new Error("Scan report not found.");
        }

        let reportData;

        try {
            reportData = JSON.parse(scan.report_json || "{}");
        } catch {
            throw new Error("The saved scan report contains invalid JSON.");
        }

        const report = {
            scan_id: scan.id,
            scanner_name: scan.scanner_name,
            scan_status: scan.scan_status,
            total_items: scan.total_items,
            suspicious_count: scan.suspicious_count,
            scan_date: scan.scan_date,
            report: reportData
        };

        const blob = new Blob(
            [JSON.stringify(report, null, 4)],
            { type: "application/json" }
        );

        url = URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = url;
        link.download = `KeyGuard_Scan_Report_${scan.id}.json`;

        document.body.appendChild(link);
        link.click();
        link.remove();

    } catch (error) {

        alert(error.message);
        console.error("Download report error:", error);

    } finally {

        if (url) {
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
    }
}


// ==========================================
// SAFE HTML ESCAPING
// ==========================================

function escapeHTML(value) {

    return String(value ?? "").replace(/[&<>"']/g, char => ({

        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"

    })[char]);
}


// ==========================================
// EXPORT SCAN HISTORY TO CSV
// ==========================================

async function exportScanHistory() {

    try {

        const response = await fetch("/api/history");

        if (!response.ok) {
            throw new Error("Failed to fetch scan history.");
        }

        const result = await response.json();

        if (!result.success || !result.history.length) {
            alert("No scan history available to export.");
            return;
        }

        const headers = [
            "Scan ID",
            "Scanner Name",
            "Status",
            "Items Scanned",
            "Suspicious Indicators",
            "Scan Date"
        ];

        function csvEscape(value) {
            return `"${String(value ?? "").replace(/"/g, '""')}"`;
        }

        const rows = result.history.map(scan => [
            scan.id,
            scan.scanner_name,
            scan.scan_status,
            scan.total_items,
            scan.suspicious_count,
            scan.scan_date
        ]);

        const csvContent = [
            headers.map(csvEscape).join(","),
            ...rows.map(row => row.map(csvEscape).join(","))
        ].join("\r\n");

        const blob = new Blob(
            ["\uFEFF" + csvContent],
            { type: "text/csv;charset=utf-8;" }
        );

        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");
        link.href = url;
        link.download = "KeyGuard_Scan_History.csv";

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        setTimeout(() => URL.revokeObjectURL(url), 1000);

    } catch (error) {

        console.error("CSV Export Error:", error);
        alert("Unable to export scan history.");

    }
}


// ==========================================
// INITIALIZE DASHBOARD
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    loadScanHistory();
    loadDashboardStatistics();

});
