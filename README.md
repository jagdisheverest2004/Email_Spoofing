
# 📧 Gmail Email Spoofing Scanner

A simple yet powerful web application built with Streamlit to analyze Gmail email headers and detect potential email spoofing attempts. The tool checks for fundamental email authentication standards like SPF, DKIM, and DMARC.

*(You should replace this with a screenshot or GIF of your actual application running)*

## 🚀 Features

  - **Two Scan Modes**:
    1.  **Live Inbox Scan**: Fetches and analyzes the most recent 'N' emails directly from your Gmail inbox.
    2.  **Raw Email Analysis**: Allows you to paste the raw content of a single email (including headers) for a detailed breakdown.
  - **Authentication Checks**: Verifies the status of SPF, DKIM, and DMARC for each email.
  - **Header Mismatch Detection**: Compares the `From` address with the `Return-Path` to spot a common indicator of spoofing.
  - **Clear Verdict**: Classifies emails as **Benign** or potentially **Malicious** based on the analysis and provides clear reasons for the verdict.
  - **User-Friendly Dashboard**: A clean and simple interface for easy use.

-----

## 🤔 How It Works

Email spoofing is a technique where an attacker forges the `From` address of an email to make it appear as if it came from a legitimate source. This tool combats that by checking the email's headers for three key authentication protocols:

  - **SPF (Sender Policy Framework)**: Checks if the IP address of the mail server that sent the email is authorized by the owner of the `From` domain. A "pass" means the server is authorized.
  - **DKIM (DomainKeys Identified Mail)**: Adds a digital signature to the email, which is verified by the receiving server. A "pass" ensures that the email's content has not been tampered with during transit.
  - **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: A policy that tells the receiving email server what to do if either SPF or DKIM checks fail (e.g., reject the message or send it to spam). A "pass" means the email aligns with the domain's DMARC policy.

The tool parses the `Authentication-Results` header to extract these values and provides a simple summary. If any of these checks fail, or if there is a suspicious mismatch between the visible sender (`From`) and the actual mail-server return path, the email is flagged.

-----

## 🛠️ Setup and Installation

Follow these steps to get the application running locally.

### Prerequisites

  - Python 3.7+
  - A Gmail Account with **2-Step Verification enabled**.
  - A **Gmail App Password**. (See security note below).

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required dependencies:**
    Create a file named `requirements.txt` and add the following line to it:

    ```
    streamlit
    ```

    Then, run the installation command:

    ```bash
    pip install -r requirements.txt
    ```

-----

## ▶️ How to Run

1.  **Run the Streamlit application from your terminal:**

    ```bash
    streamlit run app.py
    ```

    *(Assuming your Python script is named `app.py`)*

2.  **Open your web browser** and navigate to the local URL provided by Streamlit (usually `http://localhost:8501`).

3.  **Use the application:**

      - Enter your full Gmail address.
      - Enter the **16-digit Gmail App Password** you generated.
      - Choose your desired scan mode:
          - For "Scan Last N Emails", select the number of emails to check.
          - For "Paste Raw Email Content", paste the full email source (you can get this from Gmail by clicking `Show original`).
      - Click the **"🚀 Scan Emails"** button and review the results.

-----

## ⚠️ Important Security Note: Use an App Password

**DO NOT use your main Google account password in this application.**

You must use a **Gmail App Password**, which is a 16-digit passcode that gives an app or device permission to access your Google Account.

  - **Why?** App Passwords allow you to securely connect to your account from apps on less secure devices and can be revoked at any time without changing your main password.
  - **How to create one?** You can generate an App Password by following Google's official guide: [Sign in with App Passwords](https://support.google.com/accounts/answer/185833).

-----

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

-----

## ⚖️ Disclaimer

This tool is intended for educational and informational purposes. An email flagged as "Malicious" is not guaranteed to be harmful, and one flagged as "Benign" is not guaranteed to be safe. Always exercise caution when opening attachments or clicking links in any email, regardless of the analysis results.
