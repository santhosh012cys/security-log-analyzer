import streamlit as st
import pandas as pd
import re
from collections import Counter

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Security Log Analyzer")
st.caption("Cybersecurity Monitoring Dashboard")

uploaded_file = st.file_uploader(
    "📂 Upload Security Log",
    type=["log", "txt", "csv"]
)

if uploaded_file is None:
    st.info("👆 Upload your security.log file to begin analysis.")

else:
    content = uploaded_file.read().decode(
        "utf-8",
        errors="ignore"
    )

    lines = content.splitlines()

    # IP addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, content)
    ip_counts = Counter(ips)

    # Login analysis
    success_count = sum(
        "LOGIN_SUCCESS" in line
        for line in lines
    )

    failed_count = sum(
        "LOGIN_FAILED" in line
        for line in lines
    )

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📄 Total Log Lines",
            len(lines)
        )

    with col2:
        st.metric(
            "✅ Successful Logins",
            success_count
        )

    with col3:
        st.metric(
            "❌ Failed Logins",
            failed_count
        )

    with col4:
        st.metric(
            "🌐 Unique IPs",
            len(set(ips))
        )

    st.divider()

    # Security status
    st.subheader("🛡️ Security Status")

    if failed_count >= 10:
        st.error(
            "🔴 HIGH RISK — Many failed login attempts detected!"
        )

    elif failed_count >= 5:
        st.warning(
            "🟠 MEDIUM RISK — Multiple failed login attempts detected."
        )

    else:
        st.success(
            "🟢 LOW RISK — No major suspicious activity detected."
        )

    st.divider()

    # IP analysis
    st.subheader("🌐 IP Address Analysis")

    if ip_counts:

        ip_df = pd.DataFrame(
            ip_counts.items(),
            columns=["IP Address", "Attempts"]
        )

        ip_df = ip_df.sort_values(
            "Attempts",
            ascending=False
        )

        st.dataframe(
            ip_df,
            use_container_width=True,
            hide_index=True
        )

        st.subheader("🚨 Suspicious IP Addresses")

        suspicious_df = ip_df[
            ip_df["Attempts"] >= 5
        ]

        if not suspicious_df.empty:
            st.error(
                f"⚠️ {len(suspicious_df)} suspicious IP(s) detected!"
            )

            st.dataframe(
                suspicious_df,
                use_container_width=True,
                hide_index=True
            )

        else:
            st.success(
                "✅ No suspicious IP addresses detected."
            )

    else:
        st.info("No IP addresses found in the log.")

    st.divider()

    # Log preview
    st.subheader("📄 Log Preview")

    st.text_area(
        "Security Log",
        "\n".join(lines[:100]),
        height=300
    )