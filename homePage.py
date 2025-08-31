
import streamlit as st
from enum import Enum
import pandas as pd
from dashboard_seguranca import exibir_dashboard
from functions import create_issue_from_mongo_id, get_all_vulnerabilities_paginated
from main import process_scores


tab1, tab2 = st.tabs(['Oráculo', 'Dashboard'])

with tab1:

    st.title('Oráculo 🔍')
    st.write('Preencha os campos abaixo para recalcular as vulnerabilidades de acordo com sua necessidade.')

    col1, col2 = st.columns(2)

    with col1:
        company_criticality = st.slider('Criticidade para Empresa', min_value=-2.0, max_value=2.0, value=0.0, step=0.1)
        date = st.slider('Data', min_value=-2.0, max_value=2.0, value=0.0, step=0.1)


    class EnvironmentEnum(Enum):
        VAZIO = '--None--'
        PRODUCAO = 'Produção'
        HOMOLOGACAO = 'Homologação'
        INFRAESTRUTURA = 'Infraestrutura'

    with col2:
        epss = st.slider('Epss', min_value=-2.0, max_value=2.0, value=0.0, step=0.1)
        cve = st.slider('CVE', min_value=-2.0, max_value=2.0, value=0.0, step=0.1)
        
    environment = st.selectbox(
            'Ambiente',
            options=[e.value for e in EnvironmentEnum],
            index=0
        )
    
    data =  get_all_vulnerabilities_paginated(page=1)

    # Botão para calcular
    if st.button('Calcular', key='calcular', help='Clique para calcular', use_container_width=True):
        process_scores()


    # Converte os dados para um DataFrame do pandas
    if data:
        dict_data = [item for item in data if isinstance(item, dict)]
        if dict_data:
            df = pd.DataFrame(dict_data)

            # Exibe a tabela com checkboxes e botão
            st.write('### Tabela de vulnerabilidades com mais prioridade')

            selected_rows = st.dataframe(
                df,
                column_config={
                    "name": "Nome",
                    "description": "Descrição",
                    "cve_id": "CVE ID",
                    "family": "Família",
                    "epss": "EPSS",
                    "date": "Data",
                    "environments": "Ambiente",
                    "companyCriticality": "Criticidade Empresa",
                    "base_score": "Base Score",
                    "priority_class": "Classe de Prioridade",
                },
                hide_index=True,
                use_container_width=True,
                selection_mode="single-row",
                on_select="rerun",
                key="tabela_vuln"
            )

            # O botão deve aparecer sempre, mas só executar se houver seleção
            if st.button('Criar task', key='criar_task', use_container_width=True):
                idx = None
                # Verifica se selected_rows é um dicionário com seleção
                if isinstance(selected_rows, dict):
                    selection = selected_rows.get('selection') or selected_rows.get('selected_rows')
                    if selection and (isinstance(selection, dict) and selection.get('rows')):
                        idx = selection['rows'][0]
                    elif isinstance(selection, list) and selection:
                        idx = selection[0]
                # Se for lista diretamente
                elif isinstance(selected_rows, list) and selected_rows:
                    idx = selected_rows[0]
                # Se for int diretamente
                elif isinstance(selected_rows, int):
                    idx = selected_rows
                if idx is not None:
                    mongo_id = df.iloc[idx]["_id"]
                    create_issue_from_mongo_id(mongo_id, project_key="MFLP", issue_type="Task")                    
                    st.write('Task criada para:', df.iloc[idx])
                else:
                    st.warning('Selecione uma linha para criar a task.')
        else:
            st.warning('Nenhuma vulnerabilidade encontrada ou formato inválido para exibição.')
    else:
        st.warning('Nenhuma vulnerabilidade encontrada ou formato inválido para exibição.')

with tab2:
    exibir_dashboard()