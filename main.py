from detector import check_url
import csv
import os
from datetime import datetime
import customtkinter as ctk

REPORT_FILE = "report.csv"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def get_verdict(score):
    if score >= 50:
        return "Likely Phishing"
    elif score >= 20:
        return "Suspicious"
    else:
        return "Safe"


def get_threat_category(reasons):
    joined = " ".join(reasons).lower()

    if "trusted domain found in whitelist" in joined:
        return "Trusted / Safe"
    elif "impersonation" in joined or "looks similar" in joined:
        return "Brand Impersonation"
    elif "ip address" in joined:
        return "Suspicious Infrastructure"
    elif "suspicious word" in joined:
        return "Credential Theft"
    else:
        return "General Suspicious Activity"


def get_threat_confidence(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def save_to_report(url, score, verdict, threat_category, reasons):
    file_exists = os.path.exists(REPORT_FILE)
    write_header = not file_exists or os.path.getsize(REPORT_FILE) == 0

    with open(REPORT_FILE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if write_header:
            writer.writerow([
                "timestamp",
                "url",
                "risk_score",
                "verdict",
                "threat_category",
                "reasons"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            score,
            verdict,
            threat_category,
            " | ".join(reasons)
        ])


def load_report():
    if not os.path.exists(REPORT_FILE):
        return []

    with open(REPORT_FILE, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


def build_summary_text(rows):
    if not rows:
        return "No scans saved yet."

    total_scans = len(rows)
    phishing_count = sum(1 for row in rows if row["verdict"] == "Likely Phishing")
    suspicious_count = sum(1 for row in rows if row["verdict"] == "Suspicious")
    safe_count = sum(1 for row in rows if row["verdict"] == "Safe")

    lines = [
        f"Total scans: {total_scans}",
        f"Likely Phishing: {phishing_count}",
        f"Suspicious: {suspicious_count}",
        f"Safe: {safe_count}",
        "",
        "Recent scans:"
    ]

    for row in rows[-5:]:
        lines.append(
            f'{row["timestamp"]} | {row["url"]} | {row["risk_score"]} | {row["verdict"]} | {row["threat_category"]}'
        )

    return "\n".join(lines)


class ThreatSightApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ThreatSight - Phishing Detection Analyzer")
        self.geometry("1100x760")
        self.minsize(980, 680)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkFrame(self, corner_radius=18)
        header.grid(row=0, column=0, padx=18, pady=(18, 10), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="ThreatSight",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(18, 4))

        subtitle = ctk.CTkLabel(
            header,
            text="Explainable phishing detection, brand impersonation analysis, and scan history.",
            font=ctk.CTkFont(size=13)
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 18))

        # Scanner frame
        scanner = ctk.CTkFrame(self, corner_radius=18)
        scanner.grid(row=1, column=0, padx=18, pady=(0, 10), sticky="ew")
        scanner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            scanner,
            text="Enter a URL:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, padx=(18, 10), pady=18, sticky="w")

        self.url_entry = ctk.CTkEntry(
            scanner,
            placeholder_text="https://example.com",
            height=38
        )
        self.url_entry.grid(row=0, column=1, padx=10, pady=18, sticky="ew")

        scan_button = ctk.CTkButton(
            scanner,
            text="Scan URL",
            command=self.run_scan,
            height=38,
            width=120
        )
        scan_button.grid(row=0, column=2, padx=10, pady=18)

        clear_button = ctk.CTkButton(
            scanner,
            text="Clear",
            command=self.clear_fields,
            height=38,
            width=100,
            fg_color="#475569",
            hover_color="#334155"
        )
        clear_button.grid(row=0, column=3, padx=(0, 18), pady=18)

        # Results frame
        results = ctk.CTkFrame(self, corner_radius=18)
        results.grid(row=2, column=0, padx=18, pady=(0, 10), sticky="nsew")
        results.grid_columnconfigure((0, 1), weight=1)
        results.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results,
            text="Analysis Result",
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(14, 8))

        cards = ctk.CTkFrame(results, fg_color="transparent")
        cards.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=18, pady=(0, 14))
        cards.grid_columnconfigure((0, 1), weight=1)
        cards.grid_rowconfigure((0, 1), weight=1)

        self.score_card = self._make_card(cards, 0, 0, "Risk Score", "-")
        self.verdict_card = self._make_card(cards, 0, 1, "Verdict", "-")
        self.category_card = self._make_card(cards, 1, 0, "Threat Category", "-")
        self.confidence_card = self._make_card(cards, 1, 1, "Threat Confidence", "-")

        # Lower frames
        lower = ctk.CTkFrame(self, corner_radius=18, fg_color="transparent")
        lower.grid(row=3, column=0, padx=18, pady=(0, 10), sticky="nsew")
        lower.grid_columnconfigure((0, 1), weight=1)
        lower.grid_rowconfigure(0, weight=1)

        # Reasons
        reasons_frame = ctk.CTkFrame(lower, corner_radius=18)
        reasons_frame.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        reasons_frame.grid_rowconfigure(1, weight=1)
        reasons_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            reasons_frame,
            text="Reasons",
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(14, 8))

        self.reasons_text = ctk.CTkTextbox(
            reasons_frame,
            wrap="word",
            font=("Consolas", 11)
        )
        self.reasons_text.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="nsew")
        self.reasons_text.insert("end", "Scan a URL to see reasons here.")

        # History
        history_frame = ctk.CTkFrame(lower, corner_radius=18)
        history_frame.grid(row=0, column=1, padx=(8, 0), sticky="nsew")
        history_frame.grid_rowconfigure(1, weight=1)
        history_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            history_frame,
            text="Scan History",
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(14, 8))

        self.history_text = ctk.CTkTextbox(
            history_frame,
            wrap="word",
            font=("Consolas", 11)
        )
        self.history_text.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="nsew")
        self.history_text.insert("end", "No scans saved yet.")

        # Footer buttons
        footer = ctk.CTkFrame(self, corner_radius=18)
        footer_label = ctk.CTkLabel(
            footer, 
            text="ThreatSight v1.0  •  Detect. Analyze. Protect.  •  Developed by Dreavyn" ,
            font = ctk.CTkFont(size=12)
        )

        footer_label.grid(
            row=0,
            column=0,
            padx=18,
            pady=16,
            sticky="w"
        )
        footer.grid(row=4, column=0, padx=18, pady=(0, 18), sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        footer.grid_columnconfigure(1, weight=0)
        footer.grid_columnconfigure(2, weight=0)

        refresh_button = ctk.CTkButton(
            footer,
            text="Refresh History",
            command=self.refresh_history,
            height=36,
            width=140
        )
        refresh_button.grid(row=0, column=1, padx=18, pady=16, sticky="w")

        exit_button = ctk.CTkButton(
            footer,
            text="Exit",
            command=self.destroy,
            height=36,
            width=100,
            fg_color="#475569",
            hover_color="#334155"
        )
        exit_button.grid(row=0, column=2, padx=18, pady=16, sticky="e")

        self.url_entry.focus()
        self.refresh_history()

    def _make_card(self, parent, row, col, label_text, value_text):
        card = ctk.CTkFrame(parent, corner_radius=16)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=label_text,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        value = ctk.CTkLabel(
            card,
            text=value_text,
            font=ctk.CTkFont(size=18, weight="bold")
        )
        value.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 14))

        if label_text == "Verdict":
            self.verdict_value = value
        elif label_text == "Risk Score":
            self.score_value = value
        elif label_text == "Threat Category":
            self.category_value = value
        elif label_text == "Threat Confidence":
            self.confidence_value = value

        return card

    def set_verdict_style(self, verdict):
        colors = {
            "Safe": "#22c55e",
            "Suspicious": "#f59e0b",
            "Likely Phishing": "#ef4444"
        }
        self.verdict_value.configure(text=verdict, text_color=colors.get(verdict, "#e2e8f0"))

    def set_confidence_style(self, confidence):
        colors = {
            "LOW": "#22c55e",
            "MEDIUM": "#f59e0b",
            "HIGH": "#fb7185",
            "CRITICAL": "#ef4444"
        }
        self.confidence_value.configure(text=confidence, text_color=colors.get(confidence, "#e2e8f0"))

    def run_scan(self):
        url = self.url_entry.get().strip()

        if not url:
            return

        score, reasons = check_url(url)
        verdict = get_verdict(score)
        threat_category = get_threat_category(reasons)
        confidence = get_threat_confidence(score)

        self.score_value.configure(text=str(score))
        self.category_value.configure(text=threat_category)
        self.set_verdict_style(verdict)
        self.set_confidence_style(confidence)

        self.reasons_text.delete("1.0", "end")
        if reasons:
            for reason in reasons:
                self.reasons_text.insert("end", f"• {reason}\n")
        else:
            self.reasons_text.insert("end", "• No suspicious indicators found\n")

        save_to_report(url, score, verdict, threat_category, reasons)
        self.refresh_history()

    def refresh_history(self):
        rows = load_report()
        self.history_text.delete("1.0", "end")
        self.history_text.insert("end", build_summary_text(rows))

    def clear_fields(self):
        self.url_entry.delete(0, "end")
        self.score_value.configure(text="-")
        self.verdict_value.configure(text="-", text_color="#e2e8f0")
        self.category_value.configure(text="-")
        self.confidence_value.configure(text="-", text_color="#e2e8f0")
        self.reasons_text.delete("1.0", "end")
        self.reasons_text.insert("end", "Scan a URL to see reasons here.")
        self.url_entry.focus()


if __name__ == "__main__":
    app = ThreatSightApp()
    app.mainloop()