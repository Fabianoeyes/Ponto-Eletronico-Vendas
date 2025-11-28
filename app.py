import streamlit as st
import sqlite3
from datetime import datetime, date
import pandas as pd
import hashlib

DB_PATH = "ponto.db"

# =========================
# AUXILIARES DE SENHA / HASH
# =========================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

# =========================
# BANCO DE DADOS
# =========================

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # tabela de ponto
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

    # tabela de usuários
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    conn.commit()
    conn.close()

def ensure_default_admin():
    """
    Garante que exista pelo menos um admin.
    Se não houver, cria admin padrão:
      email: admin@prospera.com
      senha: Admin123!
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users WHERE is_admin = 1")
    count = cur.fetchone()["c"]
    if count == 0:
        default_email = "admin@prospera.com"
        default_pass = "Admin123!"
        cur.execute(
            "INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, 1)",
            (default_email, "Administrador", hash_password(default_pass)),
        )
        conn.commit()
        conn.close()
        return default_email, default_pass
    conn.close()
    return None, None

def get_user_by_email(email: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def create_user(name: str, email: str, password: str, is_admin: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, ?)",
        (email, name, hash_password(password), 1 if is_admin else 0),
    )
    conn.commit()
    conn.close()

def reset_user_password(email: str, new_password: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (hash_password(new_password), email),
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
    agora = datetime.utcnow().isoformat()
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

def listar_usuarios_ponto():
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
# INICIALIZAÇÃO
# =========================

st.set_page_config(page_title="Ponto & Diário de Atividades", page_icon="🕒", layout="wide")
init_db()
default_admin_email, default_admin_pass = ensure_default_admin()

if "user" not in st.session_state:
    st.session_state.user = None

# =========================
# LOGIN
# =========================

st.sidebar.title("Login")

if st.session_state.user is None:
    if default_admin_email and default_admin_pass:
        st.sidebar.info(
            f"Admin padrão criado:\n\n"
            f"Email: **{default_admin_email}**\n"
            f"Senha: **{default_admin_pass}**\n\n"
            f"Faça login e altere a senha em seguida."
        )

    login_email = st.sidebar.text_input("E-mail")
    login_password = st.sidebar.text_input("Senha", type="password")

    if st.sidebar.button("Entrar"):
        user_row = get_user_by_email(login_email)
        if user_row and verify_password(login_password, user_row["password_hash"]):
            st.session_state.user = {
                "id": user_row["id"],
                "email": user_row["email"],
                "name": user_row["name"],
                "is_admin": bool(user_row["is_admin"]),
            }
            st.experimental_rerun()
        else:
            st.sidebar.error("E-mail ou senha inválidos.")

    st.title("🕒 Ponto & Diário de Atividades")
    st.write("Faça login na barra lateral para acessar o sistema.")
    st.stop()

# Usuário logado
user = st.session_state.user
st.sidebar.success(f"Logado como: {user['name']} ({'Admin' if user['is_admin'] else 'Colaborador'})")

if st.sidebar.button("Sair"):
    st.session_state.user = None
    st.experimental_rerun()

# =========================
# VIEW COLABORADOR
# =========================

def view_colaborador(user_name: str):
    st.title("🕒 Ponto & Diário de Atividades")
    st.subheader(f"Olá, {user_name}! Registre seu dia de trabalho.")

    data_sel = st.date_input("Data", value=date.today())
    data_str = data_sel.isoformat()

    registro = get_registro(user_name, data_str)
    hora_entrada_atual = registro["hora_entrada"] if registro else ""
    hora_saida_atual = registro["hora_saida"] if registro else ""
    atividades_atual = registro["atividades"] if registro else ""

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Registro de ponto")

        if st.button("Registrar ENTRADA agora"):
            hora = datetime.now().strftime("%H:%M")
            upsert_registro(user_name, data_str, hora_entrada=hora)
            st.success(f"Entrada registrada às {hora}")
            st.experimental_rerun()

        if hora_entrada_atual:
            st.info(f"Hora de entrada: **{hora_entrada_atual}**")

        if st.button("Registrar SAÍDA agora"):
            hora = datetime.now().strftime("%H:%M")
            upsert_registro(user_name, data_str, hora_saida=hora)
            st.success(f"Saída registrada às {hora}")
            st.experimental_rerun()

        if hora_saida_atual:
            st.info(f"Hora de saída: **{hora_saida_atual}**")

    with col2:
        st.markdown("### Descritivo diário de atividades")
        atividades_input = st.text_area(
            "Descreva suas principais atividades do dia",
            value=atividades_atual,
            height=200,
        )

        if st.button("Salvar atividades do dia"):
            upsert_registro(user_name, data_str, atividades=atividades_input)
            st.success("Atividades salvas com sucesso!")

    st.markdown("---")
    st.markdown("#### Histórico recente")
    df_user = carregar_registros(usuario=user_name)
    if df_user.empty:
        st.write("Nenhum registro encontrado ainda.")
    else:
        st.dataframe(
            df_user[["data", "hora_entrada", "hora_saida", "horas_trabalhadas", "atividades"]]
        )

# =========================
# VIEW ADMIN
# =========================

def view_admin():
    st.title("📊 Painel Administrativo - Ponto & Atividades")

    st.markdown("## Gestão de usuários")

    colu1, colu2 = st.columns(2)

    with colu1:
        st.markdown("### Cadastrar novo usuário")
        new_name = st.text_input("Nome completo")
        new_email = st.text_input("E-mail do usuário")
        new_pass = st.text_input("Senha inicial", type="password")
        new_is_admin = st.checkbox("Usuário é administrador?")

        if st.button("Criar usuário"):
            if not new_name or not new_email or not new_pass:
                st.error("Preencha nome, e-mail e senha.")
            elif get_user_by_email(new_email):
                st.error("Já existe usuário com esse e-mail.")
            else:
                create_user(new_name, new_email, new_pass, new_is_admin)
                st.success("Usuário criado com sucesso!")

    with colu2:
        st.markdown("### Resetar senha de usuário existente")
        # lista emails dos usuários
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT email FROM users ORDER BY email")
        emails = [r["email"] for r in cur.fetchall()]
        conn.close()

        if emails:
            sel_email = st.selectbox("Selecione o usuário (e-mail)", options=emails)
            new_pass_reset = st.text_input("Nova senha para este usuário", type="password")
            if st.button("Resetar senha"):
                if not new_pass_reset:
                    st.error("Informe a nova senha.")
                else:
                    reset_user_password(sel_email, new_pass_reset)
                    st.success(f"Senha redefinida para {sel_email}.")
        else:
            st.info("Nenhum usuário cadastrado ainda.")

    st.markdown("---")
    st.markdown("## Registros de ponto e atividades")

    usuarios = listar_usuarios_ponto()
    usuario_filtro = st.sidebar.selectbox("Filtrar por colaborador", options=["(Todos)"] + usuarios)

    hoje = date.today()
    data_inicio = st.sidebar.date_input("Data inicial", value=date(hoje.year, 1, 1))
    data_fim = st.sidebar.date_input("Data final", value=hoje)

    if data_inicio > data_fim:
        st.sidebar.error("Data inicial não pode ser maior que a data final.")
        return

    usuario_param = None if usuario_filtro == "(Todos)" else usuario_filtro

    df = carregar_registros(
        usuario=usuario_param,
        data_inicio=data_inicio.isoformat(),
        data_fim=data_fim.isoformat(),
    )

    if df.empty:
        st.warning("Nenhum registro encontrado para os filtros selecionados.")
        return

    st.subheader("Registros detalhados")
    st.dataframe(df[["usuario", "data", "hora_entrada", "hora_saida", "horas_trabalhadas", "atividades"]])

    st.markdown("### Resumo de horas por colaborador")
    resumo = (
        df.groupby("usuario")["horas_trabalhadas"]
        .sum()
        .reset_index()
        .rename(columns={"horas_trabalhadas": "horas_totais"})
    )
    st.bar_chart(resumo.set_index("usuario"))
    st.dataframe(resumo)

    # Exportar para Excel
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

# =========================
# ROTEAMENTO POR TIPO DE USUÁRIO
# =========================

if user["is_admin"]:
    view_admin()
else:
    view_colaborador(user["name"])
