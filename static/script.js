document.addEventListener("DOMContentLoaded", () => {

  const pwInput = document.getElementById("passwordInput");
  if (pwInput) {
    const toggleBtn = document.getElementById("toggleVisibility");
    const bar = document.getElementById("strengthBar");
    const statusText = document.getElementById("liveStatus");
    const deepBtn = document.getElementById("deepAnalyzeBtn");

    toggleBtn.addEventListener("click", () => {
      const isHidden = pwInput.type === "password";
      pwInput.type = isHidden ? "text" : "password";
      toggleBtn.textContent = isHidden ? "Hide" : "Show";
    });

    pwInput.addEventListener("input", () => {
      const val = pwInput.value;
      updateCheck("chk-len12", val.length >= 12);
      updateCheck("chk-upper", /[A-Z]/.test(val));
      updateCheck("chk-lower", /[a-z]/.test(val));
      updateCheck("chk-digit", /\d/.test(val));
      updateCheck("chk-symbol", /[^A-Za-z0-9\s]/.test(val));

      if (!val) {
        bar.style.width = "0%";
        statusText.textContent = "Strength: Waiting for input...";
        return;
      }

      const res = window.zxcvbn ? zxcvbn(val.slice(0, 72)) : { score: 0 };
      const levels = [
        { label: "Weak", width: "20%", color: "#ef4444" },
        { label: "Weak", width: "35%", color: "#ef4444" },
        { label: "Medium", width: "60%", color: "#f59e0b" },
        { label: "Strong", width: "80%", color: "#22c55e" },
        { label: "Very Strong", width: "100%", color: "#10b981" },
      ];
      const lvl = levels[res.score];
      bar.style.width = lvl.width;
      bar.style.backgroundColor = lvl.color;
      statusText.textContent = `Live Strength: ${lvl.label}`;
    });

    deepBtn.addEventListener("click", async () => {
      const val = pwInput.value;
      if (!val) return alert("Please enter a password first.");
      deepBtn.textContent = "Analyzing...";
      try {
        const resp = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: val, check_breach: true }),
        });
        const data = await resp.json();

        sessionStorage.setItem("lastReport", JSON.stringify(data));
        window.location.href = "/report";
      } catch (err) {
        alert("Analysis failed. Please try again.");
      } finally {
        deepBtn.textContent = "Deep Analysis & Breach Check";
      }
    });
  }

  const genBtn = document.getElementById("generateBtn");
  if (genBtn) {
    let mode = "random";
    const lenSlider = document.getElementById("genLength");
    const wordSlider = document.getElementById("genWords");
    const output = document.getElementById("generatedOutput");

    lenSlider.addEventListener("input", () => (document.getElementById("lenValue").textContent = lenSlider.value));
    wordSlider.addEventListener("input", () => (document.getElementById("wordValue").textContent = wordSlider.value));

    document.getElementById("modeRandom").addEventListener("click", () => {
      mode = "random";
      document.getElementById("randomOptions").classList.remove("hidden");
      document.getElementById("passphraseOptions").classList.add("hidden");
    });

    document.getElementById("modePassphrase").addEventListener("click", () => {
      mode = "passphrase";
      document.getElementById("passphraseOptions").classList.remove("hidden");
      document.getElementById("randomOptions").classList.add("hidden");
    });

    genBtn.addEventListener("click", async () => {
      const payload =
        mode === "random"
          ? {
              mode: "random",
              length: parseInt(lenSlider.value, 10),
              use_upper: document.getElementById("optUpper").checked,
              use_lower: document.getElementById("optLower").checked,
              use_digits: document.getElementById("optDigits").checked,
              use_symbols: document.getElementById("optSymbols").checked,
            }
          : {
              mode: "passphrase",
              num_words: parseInt(wordSlider.value, 10),
              capitalize: document.getElementById("optCap").checked,
            };

      const resp = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      output.value = data.password;
    });

    document.getElementById("copyBtn").addEventListener("click", () => {
      if (!output.value) return;
      navigator.clipboard.writeText(output.value);
      alert("Copied to clipboard!");
    });
  }

  const reportContent = document.getElementById("reportContent");
  if (reportContent) {
    const raw = sessionStorage.getItem("lastReport");
    if (raw) {
      const data = JSON.parse(raw);
      document.getElementById("noReportMsg").classList.add("hidden");
      reportContent.classList.remove("hidden");

      document.getElementById("repCategory").textContent = data.category;
      document.getElementById("repEntropy").textContent = `${data.entropy_bits} bits`;
      document.getElementById("repBreach").textContent = data.breach.breached
        ? `Compromised (${data.breach.count.toLocaleString()}x)`
        : "Not Found in HIBP";
      document.getElementById("repDisclaimer").textContent = data.disclaimer;

      const tbody = document.getElementById("crackingTableBody");
      Object.entries(data.cracking_times).forEach(([algo, time]) => {
        tbody.innerHTML += `<tr><td>${algo}</td><td>${time}</td></tr>`;
      });

      const patList = document.getElementById("repPatterns");
      patList.innerHTML = data.patterns.length
        ? data.patterns.map((p) => `<li>${p}</li>`).join("")
        : "<li>No obvious patterns detected.</li>";

      const sugList = document.getElementById("repSuggestions");
      sugList.innerHTML = data.suggestions.map((s) => `<li>${s}</li>`).join("");

      document.getElementById("downloadPdfBtn").addEventListener("click", () => {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        doc.setFontSize(16);
        doc.text("Smart Password Security Report (Redacted)", 14, 20);
        doc.setFontSize(11);
        doc.text(`Password Analyzed: [REDACTED FOR PRIVACY] (Length: ${data.length} chars)`, 14, 32);
        doc.text(`Strength Category: ${data.category}`, 14, 42);
        doc.text(`Theoretical Entropy: ${data.entropy_bits} bits`, 14, 52);
        doc.text(`HIBP Breach Status: ${data.breach.breached ? "BREACHED" : "Clean"}`, 14, 62);
        doc.text("Recommendations:", 14, 76);
        data.suggestions.forEach((s, i) => doc.text(`- ${s}`, 14, 86 + i * 8, { maxWidth: 180 }));
        doc.save("password-security-report.pdf");
      });
    }
  }
});

function updateCheck(id, passed) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle("pass", passed);
}
