import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

def exibir_dashboard():
    data = [
    {
        "name": "Vuln A",
        "description": "Falha crítica em sistema X",
        "cve_id": "CVE-2023-1234",
        "family": "Windows",
        "epss": 0.9,
        "date": "2023-05-10",
        "environments": "Produção",
        "companyCriticality": "Crítica"
    },
    {
        "name": "Vuln B",
        "description": "Falha média em sistema Y",
        "cve_id": None,
        "family": "Linux",
        "epss": 0.3,
        "date": "2023-08-15",
        "environments": "Homologação",
        "companyCriticality": "Média"
    },
    {
        "name": "Vuln C",
        "description": "Falha crítica em sistema Z",
        "cve_id": "CVE-2024-5678",
        "family": "Aplicação",
        "epss": 0.7,
        "date": "2024-01-12",
        "environments": "Produção",
        "companyCriticality": "Crítica"
    }
]

    df = pd.DataFrame(data)
    df["date"] = pd.to_datetime(df["date"])

    # -----------------------------
    # KPIs principais
    # -----------------------------
    total_vulns = len(df)
    criticas = df[df["companyCriticality"] == "Crítica"].shape[0]
    media_epss = df["epss"].mean()
    cves_registrados = df["cve_id"].notna().sum()

    st.title("📊 Dashboard de Vulnerabilidades")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Vulnerabilidades", total_vulns)
    col2.metric("Vulns Críticas", criticas)
    col3.metric("Média EPSS", f"{media_epss:.2f}")
    col4.metric("% com CVE", f"{(cves_registrados/total_vulns)*100:.1f}%")

    # -----------------------------
    # Gráfico: Vulnerabilidades por família
    # -----------------------------
    st.subheader("🔎 Vulnerabilidades por Família")
    fig_family = px.bar(df, x="family", title="Distribuição por Família", color="family")
    st.plotly_chart(fig_family, use_container_width=True)

    # -----------------------------
    # Gráfico: Vulnerabilidades por ambiente
    # -----------------------------
    st.subheader("🌍 Vulnerabilidades por Ambiente")
    fig_env = px.pie(df, names="environments", title="Distribuição por Ambiente")
    st.plotly_chart(fig_env, use_container_width=True)

    # -----------------------------
    # Linha do tempo
    # -----------------------------
    st.subheader("📅 Evolução de Vulnerabilidades ao longo do tempo")
    timeline = df.groupby(df["date"].dt.to_period("M")).size().reset_index(name="count")
    timeline["date"] = timeline["date"].astype(str)
    fig_time = px.line(timeline, x="date", y="count", title="Novas vulnerabilidades por mês", markers=True)
    st.plotly_chart(fig_time, use_container_width=True)

    # -----------------------------
    # Heatmap Criticidade x Ambiente
    # -----------------------------
    st.subheader("🔥 Heatmap - Criticidade por Ambiente")
    heatmap_data = df.groupby(["environments", "companyCriticality"]).size().reset_index(name="count")
    fig_heatmap = px.density_heatmap(
        heatmap_data,
        x="environments",
        y="companyCriticality",
        z="count",
        color_continuous_scale="Reds",
        title="Heatmap de Criticidade x Ambiente"
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)

    # -----------------------------
    # Top 10 por EPSS
    # -----------------------------
    st.subheader("⚠️ Top 10 Vulnerabilidades por EPSS")
    top_epss = df.sort_values(by="epss", ascending=False).head(10)
    st.dataframe(top_epss[["name", "cve_id", "family", "epss", "companyCriticality"]])