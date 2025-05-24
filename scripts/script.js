let hexData = "";

function clearAll() {
  document.getElementById("hexInput").value = "";
  document.getElementById("output").textContent =
    "Ready to analyze hex data...";
  document.getElementById("analysisGrid").innerHTML = "";
  hexData = "";
}

function analyzeHex() {
  const input = document.getElementById("hexInput").value;
  const output = document.getElementById("output");

  if (!input.trim()) {
    output.textContent = "Please paste hex data first!";
    return;
  }

  // Clean and prepare hex data
  hexData = input.replace(/\s+/g, "").replace(/[^0-9A-Fa-f]/g, "");

  let analysis = "=== HEX DATA ANALYSIS ===\n\n";
  analysis += `Total hex characters: ${hexData.length}\n`;
  analysis += `Total bytes: ${hexData.length / 2}\n`;
  analysis += `Data size: ${(hexData.length / 2 / 1024).toFixed(2)} KB\n\n`;

  // Check for common file signatures
  const fileSignatures = {
    FFD8FF: "JPEG Image",
    "89504E47": "PNG Image",
    474946: "GIF Image",
    25504446: "PDF Document",
    "504B": "ZIP Archive",
    "7F454C46": "ELF Executable",
    MZ: "Windows Executable",
  };

  analysis += "=== FILE SIGNATURE ANALYSIS ===\n";
  for (const [sig, type] of Object.entries(fileSignatures)) {
    if (hexData.toUpperCase().includes(sig)) {
      analysis += `Found ${type} signature: ${sig}\n`;
    }
  }

  // Look for ASCII strings
  analysis += "\n=== ASCII CONVERSION PREVIEW ===\n";
  const asciiPreview = hexToAscii(hexData.substring(0, 200));
  analysis += asciiPreview + "\n";

  // Frequency analysis
  analysis += "\n=== BYTE FREQUENCY ANALYSIS ===\n";
  const freq = getFrequencyAnalysis(hexData);
  for (const [byte, count] of Object.entries(freq).slice(0, 10)) {
    analysis += `${byte}: ${count} times\n`;
  }

  output.textContent = analysis;
  createVisualAnalysis();
}

function convertToAscii() {
  const input = document.getElementById("hexInput").value;
  const output = document.getElementById("output");

  if (!input.trim()) {
    output.textContent = "Please paste hex data first!";
    return;
  }

  const cleanHex = input.replace(/\s+/g, "").replace(/[^0-9A-Fa-f]/g, "");
  const ascii = hexToAscii(cleanHex);

  let result = "=== ASCII CONVERSION ===\n\n";
  result += "Readable ASCII text:\n";
  result += ascii.replace(/[^\x20-\x7E\n]/g, ".") + "\n\n";
  result += "Raw ASCII (including non-printable):\n";
  result += ascii;

  output.textContent = result;
}

function findPatterns() {
  const input = document.getElementById("hexInput").value;
  const output = document.getElementById("output");

  if (!input.trim()) {
    output.textContent = "Please paste hex data first!";
    return;
  }

  const cleanHex = input.replace(/\s+/g, "").replace(/[^0-9A-Fa-f]/g, "");

  let patterns = "=== PATTERN ANALYSIS ===\n\n";

  // Look for repeating patterns
  const commonPatterns = ["20202020", "00000000", "FFFFFFFF", "2F2F2F2F"];
  patterns += "Common patterns found:\n";
  for (const pattern of commonPatterns) {
    const count = (cleanHex.match(new RegExp(pattern, "gi")) || []).length;
    if (count > 0) {
      patterns += `${pattern}: ${count} occurrences\n`;
    }
  }

  // Look for potential flag patterns
  patterns += "\nPotential flag patterns:\n";
  const flagPatterns = [
    "flag",
    "FLAG",
    "ctf",
    "CTF",
    "7b",
    "7d", // { }
    "5f", // _
    "2d", // -
  ];

  for (const pattern of flagPatterns) {
    if (cleanHex.toLowerCase().includes(pattern.toLowerCase())) {
      patterns += `Found pattern "${pattern}" in hex\n`;
    }
  }

  output.textContent = patterns;
}

function extractFiles() {
  const input = document.getElementById("hexInput").value;
  const output = document.getElementById("output");

  if (!input.trim()) {
    output.textContent = "Please paste hex data first!";
    return;
  }

  const cleanHex = input.replace(/\s+/g, "").replace(/[^0-9A-Fa-f]/g, "");

  let result = "=== FILE EXTRACTION ANALYSIS ===\n\n";

  // Look for embedded files
  const fileHeaders = {
    FFD8FF: "JPEG",
    "89504E47": "PNG",
    474946: "GIF",
    25504446: "PDF",
    "504B0304": "ZIP",
    "7F454C46": "ELF",
  };

  for (const [header, type] of Object.entries(fileHeaders)) {
    const regex = new RegExp(header, "gi");
    const matches = [...cleanHex.matchAll(regex)];
    if (matches.length > 0) {
      result += `Found ${type} file header at positions:\n`;
      matches.forEach((match) => {
        result += `  Position: ${match.index / 2} bytes\n`;
      });
      result += "\n";
    }
  }

  output.textContent = result;
}

function searchFlag() {
  const input = document.getElementById("hexInput").value;
  const output = document.getElementById("output");

  if (!input.trim()) {
    output.textContent = "Please paste hex data first!";
    return;
  }

  const cleanHex = input.replace(/\s+/g, "").replace(/[^0-9A-Fa-f]/g, "");
  const ascii = hexToAscii(cleanHex);

  let result = "=== FLAG SEARCH ===\n\n";

  // Common flag formats
  const flagPatterns = [
    /flag\{[^}]+\}/gi,
    /ctf\{[^}]+\}/gi,
    /FLAG\{[^}]+\}/gi,
    /CTF\{[^}]+\}/gi,
    /[a-zA-Z0-9_]+\{[^}]+\}/gi,
  ];

  let found = false;
  for (const pattern of flagPatterns) {
    const matches = ascii.match(pattern);
    if (matches) {
      result += "Found potential flags:\n";
      matches.forEach((flag) => {
        result += `🚩 ${flag}\n`;
      });
      found = true;
    }
  }

  if (!found) {
    result += "No standard flag format found.\n";
    result += "Searching for alternative patterns...\n\n";

    // Look for base64-like strings
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const base64Matches = ascii.match(base64Pattern);
    if (base64Matches) {
      result += "Found potential base64 strings:\n";
      base64Matches.forEach((b64) => {
        result += `📝 ${b64}\n`;
        try {
          const decoded = atob(b64);
          result += `   Decoded: ${decoded}\n`;
        } catch (e) {
          result += "   (Invalid base64)\n";
        }
      });
    }
  }

  output.textContent = result;
}

function hexToAscii(hex) {
  let ascii = "";
  for (let i = 0; i < hex.length; i += 2) {
    const byte = hex.substr(i, 2);
    const charCode = parseInt(byte, 16);
    ascii += String.fromCharCode(charCode);
  }
  return ascii;
}

function getFrequencyAnalysis(hex) {
  const freq = {};
  for (let i = 0; i < hex.length; i += 2) {
    const byte = hex.substr(i, 2).toUpperCase();
    freq[byte] = (freq[byte] || 0) + 1;
  }
  return Object.fromEntries(Object.entries(freq).sort(([, a], [, b]) => b - a));
}

function createVisualAnalysis() {
  const grid = document.getElementById("analysisGrid");

  // Create frequency chart
  const freqCard = document.createElement("div");
  freqCard.className = "analysis-card";
  freqCard.innerHTML = `
                <h3>🔢 Byte Frequency</h3>
                <div class="stats" id="freqStats"></div>
            `;

  // Create hex visualization
  const hexCard = document.createElement("div");
  hexCard.className = "analysis-card";
  hexCard.innerHTML = `
                <h3>🔍 Hex Visualization</h3>
                <div class="hex-grid" id="hexGrid"></div>
            `;

  grid.innerHTML = "";
  grid.appendChild(freqCard);
  grid.appendChild(hexCard);

  // Populate frequency stats
  const freq = getFrequencyAnalysis(hexData);
  const freqStats = document.getElementById("freqStats");
  Object.entries(freq)
    .slice(0, 8)
    .forEach(([byte, count]) => {
      const statItem = document.createElement("div");
      statItem.className = "stat-item";
      statItem.innerHTML = `<strong>${byte}</strong><br>${count}x`;
      freqStats.appendChild(statItem);
    });

  // Create hex grid visualization
  const hexGrid = document.getElementById("hexGrid");
  for (let i = 0; i < Math.min(hexData.length, 1000); i += 2) {
    const byte = hexData.substr(i, 2);
    const div = document.createElement("div");
    div.className = "hex-byte";
    div.textContent = byte;

    // Highlight interesting bytes
    const value = parseInt(byte, 16);
    if (value >= 32 && value <= 126) {
      // ASCII printable
      div.classList.add("highlight");
    }

    hexGrid.appendChild(div);
  }
}

// Auto-populate with sample data for demonstration
window.onload = function () {
  const sampleHex = `2F2F2F2F 2F2F2F2F 2F2F2F2F 2F2F2F2F 2F2F2F2F 2F2F2F2F 2F2F2F2F
20466C6167 3A202020 20202020 20202020 7656C636 6D652074 6F204354 46206368
616C6C65 6E676521 20202020 20202020 20202020 20202020 20202020 20202020`;

  // Don't auto-populate, let user paste their data
};
