import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# Simulação de dados
np.random.seed(42)

# Criticidade das vulnerabilidades
vuln_criticidade = pd.DataFrame({
    'Criticidade': ['Crítica', 'Alta', 'Média', 'Baixa'],
    'Quantidade': np.random.randint(10, 100, 4)
})

# Criticidade dos incidentes por status (simulação)
incident_criticidade_status = {
    'Total Incidentes': pd.DataFrame({
        'Criticidade': ['Crítica', 'Alta', 'Média', 'Baixa'],
        'Quantidade': np.random.randint(20, 60, 4)
    }),
    'Não Abertos': pd.DataFrame({
        'Criticidade': ['Crítica', 'Alta', 'Média', 'Baixa'],
        'Quantidade': np.random.randint(1, 10, 4)
    }),
    'Abertos': pd.DataFrame({
        'Criticidade': ['Crítica', 'Alta', 'Média', 'Baixa'],
        'Quantidade': np.random.randint(5, 30, 4)
    }),
    'Resolvidos': pd.DataFrame({
        'Criticidade': ['Crítica', 'Alta', 'Média', 'Baixa'],
        'Quantidade': np.random.randint(5, 30, 4)
    })
}

# Incidentes
incident_data = {
    'Total Incidentes': 120,
    'Não Abertos': 10,
    'Abertos': 50,
    'Resolvidos': 60
}

# Prioridade dos incidentes
incident_priority = pd.DataFrame({
    'Prioridade': ['Alta', 'Média', 'Baixa'],
    'Abertos': [12, 20, 18],
    'Resolvidos': [8, 15, 22]
})

# Incidentes por ambiente
ambiente_data = pd.DataFrame({
    'Ambiente': ['Produção', 'Homologação', 'Infraestrutura'],
    'Quantidade': [40, 35, 45]
})

# Erros por ambiente e status
def gerar_erros(ambiente):
    return {
        'Ambiente': ambiente,
        'Não Abertos': np.random.randint(1, 10),
        'Abertos': np.random.randint(5, 15),
        'Resolvidos': np.random.randint(10, 20)
    }

erros = pd.DataFrame([gerar_erros('Produção'),
                      gerar_erros('Homologação'),
                      gerar_erros('Infraestrutura')])

# Tempo médio de resolução e detecção
mttr = round(np.random.uniform(4, 12), 2)  # horas
mttd = round(np.random.uniform(1, 5), 2)

# Linha do tempo de incidentes
timeline = pd.DataFrame({
    'Data': pd.date_range(end=pd.Timestamp.today(), periods=12, freq='M'),
    'Incidentes': np.random.randint(5, 20, 12)
})

# Top ativos com mais vulnerabilidades
ativos = pd.DataFrame({
    'Ativo': [f'Servidor-{i}' for i in range(1, 6)],
    'Vulnerabilidades': np.random.randint(10, 50, 5)
})

# Layout do dashboard
st.set_page_config(layout='wide')
st.title("🔒 Dashboard de Segurança da Informação")

# === MÉTRICAS DE TOPO ===
st.subheader("📊 Visão Geral de Incidentes")
col1, col2, col3, col4 = st.columns(4)

# Seletor de status clicável
status_options = ["Total Incidentes", "Não Abertos", "Abertos", "Resolvidos"]
col_status = st.columns(4)
status_selecionado = None
for i, status in enumerate(status_options):
    if col_status[i].button(f"{status}\n{incident_data[status]}"):
        status_selecionado = status

# Se nada for clicado, mostrar Total Incidentes
if status_selecionado is None:
    status_selecionado = "Total Incidentes"


# === GRÁFICO DE CRITICIDADE DOS INCIDENTES POR STATUS ===
st.subheader(f"🛡️ Criticidade dos Incidentes - {status_selecionado}")
fig_inc_crit = px.pie(incident_criticidade_status[status_selecionado], names='Criticidade', values='Quantidade',
                      color_discrete_sequence=px.colors.sequential.Reds)
st.plotly_chart(fig_inc_crit, use_container_width=True)

# === INCIDENTES POR AMBIENTE ===
st.subheader("🌍 Incidentes por Ambiente")
fig_amb = px.pie(ambiente_data, names='Ambiente', values='Quantidade',
                 color_discrete_sequence=px.colors.qualitative.Set3)
st.plotly_chart(fig_amb, use_container_width=True)

# === PRIORIDADE DOS INCIDENTES ===
st.subheader("🚨 Incidentes por Prioridade e Status")
fig_priority = px.bar(incident_priority, x='Prioridade', y=['Abertos', 'Resolvidos'],
                      barmode='group', color_discrete_sequence=px.colors.qualitative.Pastel)
st.plotly_chart(fig_priority, use_container_width=True)

# === ERROS POR AMBIENTE ===
st.subheader("⚠️ Erros por Ambiente e Status")
st.dataframe(erros.set_index('Ambiente'))

# === MÉTRICAS COMPLEMENTARES ===
st.subheader("⏱️ Indicadores de Tempo")
col5, col6 = st.columns(2)
col5.metric("⏳ MTTR (Tempo Médio de Resolução)", f"{mttr}h")
col6.metric("🔍 MTTD (Tempo Médio de Detecção)", f"{mttd}h")

# === INCIDENTES AO LONGO DO TEMPO ===
st.subheader("📈 Evolução de Incidentes no Tempo")
fig_timeline = px.line(timeline, x='Data', y='Incidentes', markers=True,
                       line_shape='spline')
st.plotly_chart(fig_timeline, use_container_width=True)

# === TOP ATIVOS COM VULNERABILIDADES ===
st.subheader("💻 Top 5 Ativos com Mais Vulnerabilidades")
fig_ativos = px.bar(ativos, x='Ativo', y='Vulnerabilidades', color='Vulnerabilidades',
                    color_continuous_scale='Reds')
st.plotly_chart(fig_ativos, use_container_width=True)

# === BARRA LATERAL ===
st.sidebar.title("🔧 Configurações")
st.sidebar.subheader("Filtros")

# Filtro por criticidade
criticidade_selecionada = st.sidebar.multiselect(
    "Criticidade",
    options=['Crítica', 'Alta', 'Média', 'Baixa'],
    default=['Crítica', 'Alta', 'Média', 'Baixa']
)

# Filtro por ambiente
ambiente_selecionado = st.sidebar.multiselect(
    "Ambiente",
    options=ambiente_data['Ambiente'].tolist(),
    default=ambiente_data['Ambiente'].tolist()
)

# Filtro por período
st.sidebar.subheader("Período")
data_inicial = st.sidebar.date_input("Data Inicial", timeline['Data'].min())
data_final = st.sidebar.date_input("Data Final", timeline['Data'].max())
