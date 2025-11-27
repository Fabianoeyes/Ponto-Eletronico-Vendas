import hashlib
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_superadmin INTEGER DEFAULT 0,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_admin(username: str, password: str, is_superadmin: bool = False) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO admins (username, password_hash, is_superadmin, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username.strip(), hash_password(password), int(is_superadmin), brazil_now().isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_admin(username: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE username = ?", (username.strip(),))
    row = cur.fetchone()
    conn.close()
    return row


def update_admin_password(username: str, new_password: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE admins SET password_hash = ?, created_at = ? WHERE username = ?",
        (hash_password(new_password), brazil_now().isoformat(), username.strip()),
    )
    conn.commit()
    conn.close()


def validate_credentials(username: str, password: str):
    admin = get_admin(username)
    if not admin:
        return None
    if admin["password_hash"] == hash_password(password):
        return admin
    return None


def total_admins() -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM admins")
    count = cur.fetchone()[0]
    conn.close()
    return count


def list_admins():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, is_superadmin, created_at FROM admins ORDER BY is_superadmin DESC, username"
    )
    rows = cur.fetchall()
    conn.close()
    return rows

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
params = st.query_params
param_user = params.get("user", [None])[0]
param_admin = params.get("admin", [None])[0]

st.sidebar.title("Configuração de acesso")

admin_session = st.session_state.get("admin_user")
modo_admin = bool(admin_session)

# Dados lembrados localmente (no session_state do navegador)
remembered_colab = st.session_state.get("remembered_colab", "")
remember_colab_flag = st.session_state.get("remember_colab_flag", False)
remembered_admin_user = st.session_state.get("remembered_admin_user", "")
remember_admin_flag = st.session_state.get("remember_admin_flag", False)

is_first_admin_setup = total_admins() == 0

if modo_admin and param_admin != "1":
    admin_username = admin_session.get("username", "")
    admin_role = "Administrador geral" if admin_session.get("is_superadmin") else "Subadministrador"
    st.sidebar.success(f"Logado como {admin_username} ({admin_role})")
    if st.sidebar.button("Sair do modo administrador"):
        st.session_state.pop("admin_user", None)
        st.rerun()

elif is_first_admin_setup:
    st.sidebar.warning("Nenhum administrador geral cadastrado. Crie a senha principal para continuar.")
    with st.sidebar.form("criar_superadmin"):
        novo_usuario = st.text_input("Usuário do administrador geral", value="admin")
        nova_senha = st.text_input("Senha", type="password")
        confirma = st.text_input("Confirmar senha", type="password")
        submitted = st.form_submit_button("Criar administrador geral")
    if submitted:
        if not novo_usuario or not nova_senha:
            st.sidebar.error("Informe usuário e senha válidos.")
        elif nova_senha != confirma:
            st.sidebar.error("As senhas não conferem.")
        elif create_admin(novo_usuario, nova_senha, is_superadmin=True):
            st.sidebar.success("Administrador geral criado com sucesso.")
            st.session_state["admin_user"] = {"username": novo_usuario.strip(), "is_superadmin": True}
            st.rerun()
        else:
            st.sidebar.error("Usuário já existe. Escolha outro nome.")

else:
    tipo = st.sidebar.radio("Você é:", ["Colaborador", "Administrador"], index=0)
    if tipo == "Administrador":
        admin_usuario = st.sidebar.text_input("Usuário", value=remembered_admin_user)
        admin_senha = st.sidebar.text_input("Senha", type="password")
        lembrar_admin = st.sidebar.checkbox(
            "Lembrar meu usuário neste navegador",
            value=remember_admin_flag,
            help="Guarda apenas o nome de usuário neste dispositivo para facilitar o acesso.",
        )
        if st.sidebar.button("Entrar"):
            admin_data = validate_credentials(admin_usuario, admin_senha)
            if admin_data:
                st.session_state["admin_user"] = {
                    "username": admin_data["username"],
                    "is_superadmin": bool(admin_data["is_superadmin"]),
                }
                st.session_state["remember_admin_flag"] = lembrar_admin
                if lembrar_admin and admin_usuario:
                    st.session_state["remembered_admin_user"] = admin_usuario
                else:
                    st.session_state.pop("remembered_admin_user", None)
                    st.session_state["remember_admin_flag"] = False
                st.rerun()
            else:
                st.sidebar.error("Credenciais inválidas.")
                st.sidebar.info(
                    "Dica: se esqueceu a senha, peça para o administrador geral atualizar pelo painel"
                    " em 'Meus acessos'. Se não houver administrador geral acessível, renomeie o banco"
                    " ponto.db e recrie o usuário principal ao iniciar o app.",
                )
        if param_admin == "1":
            st.sidebar.info("Use seu usuário e senha para acessar o painel administrativo.")

    with st.sidebar.expander("Recuperar acesso"):
        st.markdown(
            "- Subadministradores devem solicitar ao administrador geral a redefinição da senha na seção"
            " 'Meus acessos'.\n"
            "- Se o administrador geral não tiver mais a senha, renomeie o arquivo **ponto.db** para"
            " fazer um backup e reinicie o app: um novo administrador geral poderá ser criado logo"
            " na tela inicial."
        )

# Se estiver logado, força modo admin
modo_admin = bool(st.session_state.get("admin_user"))

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
        usuario = st.sidebar.text_input("Seu nome (ou ID)", value=remembered_colab)
        lembrar_nome = st.sidebar.checkbox(
            "Lembrar meu nome neste navegador",
            value=remember_colab_flag,
            help="Grava o nome localmente para preencher automaticamente nas próximas visitas.",
        )
        st.session_state["remember_colab_flag"] = lembrar_nome
        if lembrar_nome and usuario:
            st.session_state["remembered_colab"] = usuario
        elif not lembrar_nome:
            st.session_state.pop("remembered_colab", None)
            st.session_state["remember_colab_flag"] = False
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
            st.rerun()

        if hora_entrada_atual:
            st.info(f"Hora de entrada já registrada: **{hora_entrada_atual}**")

        if st.button("Registrar SAÍDA agora"):
            hora = brazil_now().strftime("%H:%M")
            upsert_registro(usuario, data_str, hora_saida=hora)
            st.success(f"Saída registrada às {hora}")
            st.rerun()

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

    admin_logado = st.session_state.get("admin_user", {})
    papel = "Administrador geral" if admin_logado.get("is_superadmin") else "Subadministrador"
    st.info(f"Acesso autenticado como **{admin_logado.get('username', '')}** ({papel}).")

    st.markdown("### Gerenciar administradores")
    if admin_logado.get("is_superadmin"):
        st.success("Você é o administrador geral e pode criar subadministradores.")
        with st.form("criar_subadmin"):
            novo_admin = st.text_input("Usuário do novo administrador")
            senha_admin = st.text_input("Senha do novo administrador", type="password")
            confirma_admin = st.text_input("Confirmar senha", type="password")
            criado = st.form_submit_button("Cadastrar subadministrador")

        if criado:
            if not novo_admin or not senha_admin:
                st.error("Informe usuário e senha para o novo administrador.")
            elif senha_admin != confirma_admin:
                st.error("As senhas não conferem.")
            elif create_admin(novo_admin, senha_admin, is_superadmin=False):
                st.success(f"Subadministrador '{novo_admin}' criado com sucesso.")
            else:
                st.error("Usuário já existe. Tente outro nome de acesso.")
    else:
        st.warning("Apenas o administrador geral pode criar novos administradores.")

    with st.expander("Meus acessos", expanded=False):
        with st.form("atualizar_senha_admin"):
            nova_senha_admin = st.text_input("Nova senha", type="password")
            confirma_nova = st.text_input("Confirmar nova senha", type="password")
            alterar = st.form_submit_button("Atualizar minha senha")

        if alterar:
            if not nova_senha_admin:
                st.error("Informe a nova senha.")
            elif nova_senha_admin != confirma_nova:
                st.error("As senhas não conferem.")
            else:
                update_admin_password(admin_logado.get("username", ""), nova_senha_admin)
                st.success("Senha atualizada com sucesso.")

    admins_cadastrados = list_admins()
    if admins_cadastrados:
        st.markdown("#### Administradores cadastrados")
        df_admins = pd.DataFrame(admins_cadastrados)
        df_admins = df_admins.rename(
            columns={
                "username": "Usuário",
                "is_superadmin": "Administrador geral",
                "created_at": "Atualizado em",
            }
        )
        df_admins["Administrador geral"] = df_admins["Administrador geral"].apply(lambda x: "Sim" if x else "Não")
        st.dataframe(df_admins)

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
