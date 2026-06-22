# 🛡️ SENTINEL — AI-Driven Cyber Resilience for Critical National Infrastructure

**Problem Statement 7** | Production-Ready Flask Web Application

An AI-powered cybersecurity platform that correlates network flow anomalies with authentication log anomalies using Isolation Forest ML to detect low-and-slow Advanced Persistent Threats (APTs) with **95% reduction in false positives**.

---

## 🎯 What It Does

| Feature | Description |
|---------|-------------|
| **AI Detection** | Isolation Forest ML on network + auth data, then cross-source correlation |
| **Explainable AI** | Every alert shows exact host, user, time range, and MITRE ATT&CK technique |
| **SOAR Simulation** | One-click host isolation with visual feedback |
| **Custom Data Upload** | Upload your own CSVs and run detection instantly |
| **Deterministic Pipeline** | Same results every run for reliable demos |

---

## 🏆 Key Results

```
Network-only detection:    8 attacks caught, 77 false positives
Auth-only detection:      31 attacks caught, 57 false positives
Sentinel Mesh (correlated): 2 attacks caught, 1 false positive
                            → 95% reduction in false positives!
```

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install flask pandas numpy scikit-learn

# Run the application
python app.py

# Open browser to http://127.0.0.1:5000/login
# Login with: admin / admin123
```

---

## 📊 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 + Flask |
| ML/AI | scikit-learn (Isolation Forest) |
| Data | pandas, numpy |
| Frontend | HTML5 + Jinja2 |
| Styling | Tailwind CSS |
| Charts | Chart.js |

---

## 📁 Project Structure

```
├── app.py                    # Main Flask application
├── generate_data.py          # Synthetic data generation
├── detect.py                 # ML detection + correlation
├── attack_mapping.py         # MITRE ATT&CK mapping
├── templates/
│   ├── base.html             # Master layout
│   ├── login.html            # Login page
│   ├── dashboard.html        # Main dashboard
│   ├── network.html          # Network flows view
│   ├── auth_view.html        # Auth logs view
│   ├── upload.html           # CSV upload + detection
│   ├── settings.html         # Parameter controls
│   └── about.html            # Documentation
└── PROJECT_WALKTHROUGH.md    # Complete walkthrough
```

---

## 🎬 Demo

- **Dashboard:** Real-time correlated alerts with MITRE ATT&CK mapping
- **Isolation:** Click-to-isolate compromised hosts with visual feedback
- **Upload:** Run detection on your own CSV data
- **Explainable:** Every alert has reasoning + ground truth

---

## 🔐 Login Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| analyst | analyst456 | Security Analyst |
| viewer | viewer789 | Viewer |

---

## 📖 Documentation

- `PROJECT_WALKTHROUGH.md` — Complete technical walkthrough
- `POST_LOGIN_STEPS.md` — Step-by-step demo script for presentations

---

## 🎯 Attack Scenario Demonstrated

1. **Low-and-slow brute force** on HOST-007/user09 (hours 30-36)
2. **Lateral movement + exfiltration** (hours 40-42)
3. **Cross-source correlation** catches both with high confidence

---

## 📄 License

This is a prototype for educational/demonstration purposes.

---

*Built for AI-Driven Cyber Resilience in Critical National Infrastructure*