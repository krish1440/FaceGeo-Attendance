# 👁️‍🗨️ FaceGeo: Revolutionizing Attendance Management

Welcome to **FaceGeo**, a smart attendance management system that combines **facial recognition** and **geo-fencing** technologies for secure, efficient, and fraud-proof attendance tracking — ideal for companies and educational institutions.

---

## 🚀 Key Features

### 🔒 Secure Login & Admin Dashboard
- Role-based access for organizations and users
- Password-protected secure access

### 🧠 Facial Recognition
- AI-powered identity verification using state-of-the-art facial recognition

### 📍 Location Tracking (Geo-Fencing)
- Define authorized zones to ensure accurate location-based check-ins

### 🔁 Real-Time Capture & Verification
- Instant attendance marking with dual verification (Face + Location)

### 📊 Attendance Analytics & Reports
- Downloadable summaries
- Visual dashboards for monitoring performance and attendance patterns

---

## 💻 Web Dashboard Screens

| Dashboard               | Description                                                                      |
|-------------------------|----------------------------------------------------------------------------------|
| 👤 **User Dashboard**     | Attendance check-in, attendance tracking, export reports, manual request submission |
| 🏢 **Organization Dashboard** | User management, attendance tracking, export reports                              |

---

## 🧑‍💼 User Flow

1. **Login**
2. **Verify Face & Location**
3. **Attendance Marked**
4. **View Attendance Records**

✅ Optional: Submit manual request if automated check-in fails.

---

## 🏢 Organization Flow

1. **Register Organization**
2. **Set Attendance Zones**
3. **Add Users**
4. **Monitor & Approve**
5. **Download Reports**

---

## ⚙️ Tech Stack

- **Frontend**: HTML, CSS, JavaScript  
- **Backend**: Flask  
- **Database**: Supabase  

---

## 📈 Benefits

- ✅ **Fraud Prevention**: Eliminates proxy attendance (no more buddy punching)
- ⏱ **Time-Saving**: Automates entire attendance workflow
- 📱 **Cross-Platform**: Accessible via web & mobile
- 📌 **Insightful Data**: View attendance trends and percentages

---

## 🧑‍🤝‍🧑 Meet the Team — Team DataMind

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/krish1440" target="_blank">
        <img src="https://github.com/krish1440.png" width="100px;" alt="Krish Chaudhary"/><br />
        <img src="https://img.icons8.com/ios-glyphs/20/ffffff/github.png" width="15px"/> <sub><b>Krish Chaudhary</b></sub>
      </a><br />
      <sub><i>Data Scientist, ML/DL Engineer</i></sub><br />
      <sub>Specializes in Data Science, Machine Learning, and Deep Learning. Focuses on building AI models that power automation and smart analytics.</sub>
    </td>
    <td align="center">
      <a href="https://github.com/Raj-Kapuriya" target="_blank">
        <img src="https://github.com/Raj-Kapuriya.png" width="100px;" alt="Raj Kapuriya"/><br />
        <img src="https://img.icons8.com/ios-glyphs/20/ffffff/github.png" width="15px"/> <sub><b>Raj Kapuriya</b></sub>
      </a><br />
      <sub><i>AI Engineer, Data Scientist</i></sub><br />
      <sub>Expert in AI and data systems. Focuses on deploying machine learning models that enhance performance and decision-making.</sub>
    </td>
  </tr>
</table>

---

## 🌐 Web App Live

🔗 [FaceGeo Attendance App (on Render)](https://facegeo-attendance.onrender.com/)

---

## ⚙️ Installation & Setup

```bash
# Clone the repo
git clone https://github.com/krish1440/facegeo.git
cd facegeo

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
