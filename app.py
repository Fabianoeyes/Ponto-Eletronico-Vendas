import sqlite3
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo
import urllib.parse

import pandas as pd
import streamlit as st

DB_PATH = "ponto.db"
BRAZIL_TZ = ZoneInfo("America/Sao_Paulo")
LOGO_PATH = Path("assets/prospera-logo.svg")
DEFAULT_BASE_URL = "https://ponto-eletronico-vendas.streamlit.app"

# =========================
# Funções de banco de dados
# =========================
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def brazil_now():
    """Retorna o horário atual no fuso de Brasília."""
    return datetime.now(BRAZIL_TZ)

def render_header(title: str, subtitle: str | None = None):
    """Renderiza o cabeçalho com o logo da Prospera no canto superior direito."""
    title_col, logo_col = st.columns([6, 1])
    with title_col:
        st.title(title)
        if subtitle:
            st.caption(subtitle)
    with logo_col:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), width=110)
        else:
            st.markdown("<div style='text-align:right;'>Prospera</div>", unsafe_allow_html=True)

def gerar_link_personalizado(nome: str, base_url: str = DEFAULT_BASE_URL) -> str:
    """Monta um link de compartilhamento para um colaborador/vendedor específico."""
    base_limpo = base_url.strip().rstrip("/")
    if not base_limpo or not nome.strip():
        return ""
    nome_codificado = urllib.parse.quote(nome.strip())
    return f"{base_limpo}?user={nome_codificado}"

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pontos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            data TEXT NOT NULL,
            hora_entrada TEXT,
            hora_saida TEXT,
            atividades TEXT,
            criado_em TEXT,
            atualizado_em TEXT
        )
        """
    )
    conn.commit()
    conn.close()

def get_registro(usuario: str, data_str: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM pontos WHERE usuario = ? AND data = ? ORDER BY id DESC LIMIT 1",
        (usuario, data_str),
    )
    row = cur.fetchone()
    conn.close()
    return row

def upsert_registro(usuario: str, data_str: str, hora_entrada: str = None,
                    hora_saida: str = None, atividades: str = None):
    """Cria ou atualiza o registro de ponto do usuário na data."""
    agora = brazil_now().isoformat()
    registro = get_registro(usuario, data_str)

    conn = get_connection()
    cur = conn.cursor()

    if registro is None:
        cur.execute(
            """
            INSERT INTO pontos (usuario, data, hora_entrada, hora_saida, atividades, criado_em, atualizado_em)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (usuario, data_str, hora_entrada, hora_saida, atividades or "", agora, agora),
        )
    else:
        nova_hora_entrada = hora_entrada or registro["hora_entrada"]
        nova_hora_saida = hora_saida or registro["hora_saida"]
        novas_atividades = atividades if atividades is not None else registro["atividades"]
        cur.execute(
            """
            UPDATE pontos
            SET hora_entrada = ?, hora_saida = ?, atividades = ?, atualizado_em = ?
            WHERE id = ?
            """,
            (nova_hora_entrada, nova_hora_saida, novas_atividades, agora, registro["id"]),
        )
    conn.commit()
    conn.close()

def listar_usuarios():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT usuario FROM pontos ORDER BY usuario")
    usuarios = [r["usuario"] for r in cur.fetchall()]
    conn.close()
    return usuarios

def carregar_registros(usuario: str = None, data_inicio: str = None, data_fim: str = None):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT * FROM pontos WHERE 1=1"
    params = []

    if usuario:
        query += " AND usuario = ?"
        params.append(usuario)
    if data_inicio:
        query += " AND data >= ?"
        params.append(data_inicio)
    if data_fim:
        query += " AND data <= ?"
        params.append(data_fim)

    query += " ORDER BY data DESC, usuario"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame([dict(r) for r in rows])

    # calcula horas trabalhadas (se entrada e saída existem)
    def calc_horas(row):
        he = row.get("hora_entrada")
        hs = row.get("hora_saida")
        if not he or not hs:
            return None
        try:
            t1 = datetime.strptime(he, "%H:%M")
            t2 = datetime.strptime(hs, "%H:%M")
            delta = t2 - t1
            return round(delta.total_seconds() / 3600, 2)
        except Exception:
            return None

    df["horas_trabalhadas"] = df.apply(calc_horas, axis=1)
    return df

# =========================
# Layout / lógica
# =========================
init_db()
st.set_page_config(page_title="Ponto & Diário de Atividades", page_icon="🕒", layout="wide")

# Lê parâmetros da URL (?user=Fulano&admin=1)
params = st.experimental_get_query_params()
param_user = params.get("user", [None])[0]
param_admin = params.get("admin", [None])[0]

st.sidebar.title("Configuração de acesso")

modo_admin = False
if param_admin == "1":
    modo_admin = True
else:
    # opção simples de login admin com senha fixa (pode trocar)
    tipo = st.sidebar.radio("Você é:", ["Colaborador", "Administrador"])
    if tipo == "Administrador":
        senha = st.sidebar.text_input("Senha de administrador", type="password")
        if senha == "prospera_admin":  # troque por algo mais seguro
            modo_admin = True
        else:
            if senha:
                st.sidebar.error("Senha inválida. Usando modo colaborador.")

# =========================
# MODO COLABORADOR
# =========================
if not modo_admin:
    render_header(
        "🕒 Ponto e Diário de Atividades",
        "Horários registrados no fuso horário de Brasília (America/Sao_Paulo).",
    )

    # Identificação do colaborador
    if param_user:
        usuario = param_user
        st.sidebar.success(f"Usuário detectado via link: {usuario}")
    else:
        usuario = st.sidebar.text_input("Seu nome (ou ID)", value="")
        st.sidebar.info("Você também pode receber um link do tipo ?user=SeuNome")

    if not usuario:
        st.warning("Informe seu nome na barra lateral para continuar.")
        st.stop()

    st.subheader(f"Olá, {usuario}! Registre seu dia de trabalho.")
    base_para_links = st.sidebar.text_input(
        "URL base do app",
        value=DEFAULT_BASE_URL,
        help="Use esta URL para gerar links personalizados com o parâmetro ?user=Nome",
    )
    link_usuario = gerar_link_personalizado(usuario, base_para_links)
    if link_usuario:
        st.sidebar.code(link_usuario, language="text")
        st.sidebar.caption("Compartilhe este link com o colaborador para acesso rápido.")

    # Data da atividade
    data_sel = st.date_input("Data", value=date.today())
    data_str = data_sel.isoformat()

    # Carrega registro existente (se houver)
    registro = get_registro(usuario, data_str)
    hora_entrada_atual = registro["hora_entrada"] if registro else ""
    hora_saida_atual = registro["hora_saida"] if registro else ""
    atividades_atual = registro["atividades"] if registro else ""

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Registro de ponto")

        if st.button("Registrar ENTRADA agora"):
            hora = brazil_now().strftime("%H:%M")
            upsert_registro(usuario, data_str, hora_entrada=hora)
            st.success(f"Entrada registrada às {hora}")
            st.experimental_rerun()

        if hora_entrada_atual:
            st.info(f"Hora de entrada já registrada: **{hora_entrada_atual}**")

        if st.button("Registrar SAÍDA agora"):
            hora = brazil_now().strftime("%H:%M")
            upsert_registro(usuario, data_str, hora_saida=hora)
            st.success(f"Saída registrada às {hora}")
            st.experimental_rerun()

        if hora_saida_atual:
            st.info(f"Hora de saída já registrada: **{hora_saida_atual}**")

    with col2:
        st.markdown("### Descritivo diário de atividades")
        atividades_input = st.text_area(
            "Descreva suas principais atividades do dia",
            value=atividades_atual,
            height=200,
        )

        if st.button("Salvar atividades do dia"):
            upsert_registro(usuario, data_str, atividades=atividades_input)
            st.success("Atividades salvas com sucesso!")

    st.markdown("---")
    st.markdown("#### Histórico recente")
    df_user = carregar_registros(usuario=usuario)
    if df_user.empty:
        st.write("Nenhum registro encontrado ainda.")
    else:
        st.dataframe(
            df_user[["data", "hora_entrada", "hora_saida", "horas_trabalhadas", "atividades"]]
        )

    st.info(
        "Dica: salve o link deste app com `?user=SeuNome` nos favoritos do navegador "
        "para usar como ponto eletrônico diário."
    )

# =========================
# MODO ADMINISTRADOR
# =========================
else:
    render_header(
        "📊 Painel Administrativo - Ponto & Atividades",
        "Controle centralizado de pontos e diário de atividades (fuso de Brasília).",
    )

    st.sidebar.success("Modo administrador ativo")

    st.markdown("### Links de convite para vendedores")
    base_para_links_admin = st.text_input(
        "URL base do app",
        value=DEFAULT_BASE_URL,
        help="Informe a URL publicada do app para gerar convites com ?user=NomeDoVendedor",
    )
    nome_vendedor = st.text_input("Nome do vendedor para gerar link", placeholder="Ex.: Ana Souza")
    link_convite = gerar_link_personalizado(nome_vendedor, base_para_links_admin)
    if link_convite:
        st.code(link_convite, language="text")
        st.caption("Envie este link para que o vendedor já entre identificado no app.")

    # Filtros
    usuarios = listar_usuarios()
    usuario_filtro = st.sidebar.selectbox("Filtrar por colaborador", options=["(Todos)"] + usuarios)

    hoje = date.today()
    data_inicio = st.sidebar.date_input("Data inicial", value=date(hoje.year, 1, 1))
    data_fim = st.sidebar.date_input("Data final", value=hoje)

    if data_inicio > data_fim:
        st.sidebar.error("Data inicial não pode ser maior que a data final.")
        st.stop()

    usuario_param = None if usuario_filtro == "(Todos)" else usuario_filtro

    df = carregar_registros(
        usuario=usuario_param,
        data_inicio=data_inicio.isoformat(),
        data_fim=data_fim.isoformat(),
    )

    if df.empty:
        st.warning("Nenhum registro encontrado para os filtros selecionados.")
        st.stop()

    horas_validas = df["horas_trabalhadas"].fillna(0).sum()
    total_registros = len(df)
    col_metricas = st.columns(3)
    col_metricas[0].metric("Registros no período", total_registros)
    col_metricas[1].metric("Horas somadas", f"{horas_validas:.2f} h")
    col_metricas[2].metric("Colaboradores únicos", df["usuario"].nunique())

    st.subheader("Registros de ponto e atividades")
    st.dataframe(df[["usuario", "data", "hora_entrada", "hora_saida", "horas_trabalhadas", "atividades"]])

    # Resumo por colaborador
    st.markdown("### Resumo de horas por colaborador")

    resumo = (
        df.groupby("usuario")["horas_trabalhadas"]
        .sum()
        .reset_index()
        .rename(columns={"horas_trabalhadas": "horas_totais"})
    )

    st.bar_chart(resumo.set_index("usuario"))

    st.markdown("### Tabela resumo")
    st.dataframe(resumo)

    st.markdown("### Exportar para Excel")
    excel = df.to_excel(index=False, sheet_name="Ponto", engine="xlsxwriter")
    # streamlit aceita bytes diretamente; vamos gerar de forma simples:
    import io
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Ponto")
    st.download_button(
        "Baixar planilha XLSX",
        data=output.getvalue(),
        file_name="ponto_colaboradores.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
