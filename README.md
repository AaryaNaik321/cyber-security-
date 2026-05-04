# cyber-security-
🚨 Cyber Threat Detector

An AI-powered Cyber Threat Detection Web App built with Streamlit and Google Gemini that analyzes security logs, detects threats, and provides actionable insights.

📄 Based on your project documentation

🔍 Overview

Cyber Threat Detector is a web application that allows users to:

Analyze security logs using AI
Detect cyber threats like:
Phishing
SQL Injection
DDoS
Malware / Ransomware
Brute Force Attacks
Upload and analyze CSV datasets
Receive Telegram alerts
Store and review past analyses
✨ Features
🧠 AI-Powered Analysis
Uses Google Gemini (gemini-2.5-flash) model
Returns structured results:
Threat name
Severity
Confidence score
Prevention steps
Recommended tools
📄 Multiple Input Modes
Single log text analysis
Synthetic demo data (quick testing)
CSV dataset analysis:
Full dataset summary
Row-by-row analysis
📊 Insights & Visualization
Dataset metrics (rows, columns, flagged logs)
Event type breakdown
Threat severity classification
📩 Telegram Notifications
Sends alerts for:
Detected threats 🚨
No-threat cases ✅
🗂 History Tracking
Stores results in a local JSON file
View past threat analyses
Clear history anytime
🏗 Architecture
User Input (Text / CSV)
        ↓
Streamlit UI (app.py)
        ↓
Gemini Analyzer (AI Processing)
        ↓
Result Processing & Normalization
        ↓
 ├── Display in UI
 ├── Save to History (JSON)
 └── Send Telegram Notification
📁 Project Structure
.
├── app.py                      # Main Streamlit app
├── gemini_analyzer.py          # AI logic (Gemini API)
├── csv_dataset.py              # CSV processing
├── data.py                     # Synthetic logs
├── telegram_notifier.py        # Telegram alerts
├── requirements.txt            # Dependencies
├── history/
│   └── threats_history.json    # Stored results
├── security_logs_200_points.csv # Example dataset
└── DOCUMENTATION.md
⚙️ Installation
1. Clone the repository
git clone https://github.com/your-username/cyber-threat-detector.git
cd cyber-threat-detector
2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
3. Install dependencies
pip install -r requirements.txt
🔑 Configuration
Google Gemini API

Set your API key in gemini_analyzer.py or as environment variable:

GEMINI_API_KEY=your_api_key
Telegram Setup

In telegram_notifier.py:

TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
▶️ Run the App
streamlit run app.py

Open in browser:

http://localhost:8501
🧑‍💻 How to Use
1. Single Log Analysis
Paste a security log
Click Analyze with AI
View structured threat output
2. Load Demo Data
Click Load Data for instant testing
3. CSV Analysis
Upload CSV file
View dataset insights
Run:
Full dataset AI analysis
Row-by-row analysis
4. History
View past analyses
Clear history if needed
📊 Example Output
Threat Name: SQL Injection Attempt
Severity: High
Confidence: 92%
Prevention:
Input validation
Prepared statements
Immediate Actions:
Block IP
Review logs
📦 Dependencies
streamlit
google-genai
pandas
requests
plotly (optional)
⚠️ Security Notes
Do NOT commit API keys
Logs may contain sensitive data (IP, usernames)
Use environment variables for secrets
Ensure compliance before analyzing real production logs
🚀 Future Improvements
Real-time log monitoring
Dashboard visualizations
Model fine-tuning
Multi-user authentication
Cloud deployment
📜 License

This project is for educational and research purposes.

🙌 Contribution

Feel free to fork, improve, and submit pull requests.
