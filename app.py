import streamlit as st
import sqlite3
import secrets
from datetime import datetime, date, timedelta
import pandas as pd
import pyotp
import hashlib

DB_PATH = "ponto.db"


def normalize_email(email: str) -> str:
    """Sanitize email addresses to avoid mismatches caused by spacing or casing."""
    return email.strip().lower()

# =========================
# AUXILIARES DE SENHA / HASH
# =========================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def generate_recovery_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

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
    ensure_user_columns(conn)
    conn.close()


def ensure_user_columns(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in cur.fetchall()}

    columns_to_add = []
    if "phone" not in existing_columns:
        columns_to_add.append("ALTER TABLE users ADD COLUMN phone TEXT")
    if "recovery_method" not in existing_columns:
        columns_to_add.append("ALTER TABLE users ADD COLUMN recovery_method TEXT")
    if "totp_secret" not in existing_columns:
        columns_to_add.append("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "recovery_code" not in existing_columns:
        columns_to_add.append("ALTER TABLE users ADD COLUMN recovery_code TEXT")
    if "recovery_expires_at" not in existing_columns:
        columns_to_add.append("ALTER TABLE users ADD COLUMN recovery_expires_at TEXT")

    for ddl in columns_to_add:
        cur.execute(ddl)
    if columns_to_add:
        conn.commit()


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
        conn.close()
        create_user(
            name="Administrador",
            email=default_email,
            password=default_pass,
            is_admin=True,
            recovery_method="Email",
        )
        return default_email, default_pass
    conn.close()
    return None, None

def get_user_by_email(email: str):
    email = normalize_email(email)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def create_user(
    name: str,
    email: str,
    password: str,
    is_admin: bool,
    phone: str | None = None,
    recovery_method: str = "Email",
):
    email = normalize_email(email)
    conn = get_connection()
    cur = conn.cursor()
    totp_secret = generate_totp_secret() if recovery_method == "Authenticator" else None
    cur.execute(
        """
        INSERT INTO users (email, name, password_hash, is_admin, phone, recovery_method, totp_secret)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            name,
            hash_password(password),
            1 if is_admin else 0,
            phone,
            recovery_method,
            totp_secret,
        ),
    )
    conn.commit()
    conn.close()
    return totp_secret

def reset_user_password(email: str, new_password: str):
    email = normalize_email(email)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (hash_password(new_password), email),
    )
    conn.commit()
    conn.close()


def set_recovery_code(email: str, code: str, expires_at: datetime):
    email = normalize_email(email)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET recovery_code = ?, recovery_expires_at = ? WHERE email = ?",
        (code, expires_at.isoformat(), email),
    )
    conn.commit()
    conn.close()


def clear_recovery_state(email: str):
    email = normalize_email(email)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET recovery_code = NULL, recovery_expires_at = NULL WHERE email = ?",
        (email,),
    )
    conn.commit()
    conn.close()


def reset_all_users():
    """Remove todos os usuários e recria o admin padrão."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users")
    conn.commit()
    conn.close()
    return ensure_default_admin()

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


def listar_recuperacoes_pendentes():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT email, recovery_method, recovery_expires_at, recovery_code
        FROM users
        WHERE recovery_code IS NOT NULL
        ORDER BY recovery_expires_at DESC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

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

    with st.sidebar.expander("Novo cadastro"):
        new_name_public = st.text_input("Nome completo", key="public_name")
        new_email_public = st.text_input("E-mail corporativo", key="public_email")
        new_pass_public = st.text_input("Senha", type="password", key="public_pass1")
        new_pass_public_conf = st.text_input(
            "Confirmar senha", type="password", key="public_pass2"
        )
        role_public = st.radio(
            "Perfil de acesso", ["Colaborador", "Administrador"], index=0, key="public_role"
        )
        if st.button("Criar conta", key="create_public_account"):
            if not new_name_public or not new_email_public or not new_pass_public:
                st.error("Preencha nome, e-mail e senha para criar a conta.")
            elif new_pass_public != new_pass_public_conf:
                st.error("As senhas informadas não conferem.")
            elif get_user_by_email(new_email_public):
                st.error("Já existe um usuário com este e-mail.")
            else:
                create_user(
                    name=new_name_public,
                    email=new_email_public,
                    password=new_pass_public,
                    is_admin=role_public == "Administrador",
                    recovery_method="Email",
                )
                st.success("Conta criada com sucesso! Faça login com suas credenciais.")

    with st.sidebar.expander("Esqueci a senha"):
        recovery_email = st.text_input("E-mail cadastrado", key="recover_email")
        recovery_method_choice = st.selectbox(
            "Método de recuperação", ["Email", "SMS", "Authenticator"], key="recover_method"
        )
        user_row_for_recovery = get_user_by_email(recovery_email) if recovery_email else None
        if user_row_for_recovery:
            preferred = user_row_for_recovery["recovery_method"] or "Email"
            st.caption(f"Método preferencial deste usuário: **{preferred}**")
        if st.button("Gerar código de recuperação", key="generate_recovery_code"):
            if not user_row_for_recovery:
                st.error("E-mail não encontrado.")
            elif user_row_for_recovery["recovery_method"] and (
                recovery_method_choice != user_row_for_recovery["recovery_method"]
            ):
                st.warning(
                    "Método selecionado diferente do cadastrado. Use o método preferencial para maior segurança."
                )
            if user_row_for_recovery:
                if recovery_method_choice in ["Email", "SMS"]:
                    code = generate_recovery_code()
                    expires_at = datetime.utcnow() + timedelta(minutes=15)
                    set_recovery_code(recovery_email, code, expires_at)
                    st.success(
                        f"Código gerado e enviado via {recovery_method_choice}. (Uso interno: {code})"
                    )
                    st.caption(
                        "Em produção, o código seria enviado. Ele expira em 15 minutos."
                    )
                else:
                    if not user_row_for_recovery["totp_secret"]:
                        st.error(
                            "Método Authenticator não configurado para este usuário. "
                            "Peça ao administrador para gerar uma chave."
                        )
                    else:
                        st.info(
                            "Abra seu aplicativo autenticador (Google Authenticator, Authy, etc.) "
                            "e use o código de 6 dígitos atual."
                        )

        recovery_code_input = st.text_input(
            "Código recebido ou gerado pelo app", key="recovery_code_input"
        )
        new_pass1 = st.text_input("Nova senha", type="password", key="recover_new1")
        new_pass2 = st.text_input(
            "Confirmar nova senha", type="password", key="recover_new2"
        )
        if st.button("Atualizar senha esquecida", key="reset_from_recovery"):
            user_row = get_user_by_email(recovery_email)
            if not user_row:
                st.error("E-mail não encontrado.")
            elif not new_pass1 or not new_pass2:
                st.error("Informe e confirme a nova senha.")
            elif new_pass1 != new_pass2:
                st.error("As senhas não conferem.")
            else:
                preferred_method = user_row["recovery_method"] or recovery_method_choice
                if preferred_method == "Authenticator":
                    if not user_row["totp_secret"]:
                        st.error(
                            "Nenhum autenticador configurado para este usuário. Peça ao administrador para configurar."
                        )
                    else:
                        totp = pyotp.TOTP(user_row["totp_secret"])
                        if not recovery_code_input:
                            st.error("Informe o código do aplicativo autenticador.")
                        elif not totp.verify(recovery_code_input, valid_window=1):
                            st.error("Código do autenticador inválido ou expirado.")
                        else:
                            reset_user_password(recovery_email, new_pass1)
                            clear_recovery_state(recovery_email)
                            st.success("Senha atualizada com sucesso. Faça login novamente.")
                else:
                    stored_code = user_row["recovery_code"]
                    expires_raw = user_row["recovery_expires_at"]
                    if not stored_code or not expires_raw:
                        st.error("Nenhum código de recuperação ativo. Gere um novo código.")
                    else:
                        expires_at = datetime.fromisoformat(expires_raw)
                        if datetime.utcnow() > expires_at:
                            st.error("Código expirado. Gere um novo código de recuperação.")
                        elif recovery_code_input != stored_code:
                            st.error("Código inválido.")
                        else:
                            reset_user_password(recovery_email, new_pass1)
                            clear_recovery_state(recovery_email)
                            st.success(
                                "Senha atualizada com sucesso. Você já pode fazer login com a nova senha."
                            )

    with st.sidebar.expander("Reset geral de logins"):
        st.caption(
            "Remove todos os usuários cadastrados e recria apenas o admin padrão para que o "
            "cadastro recomece do zero."
        )
        if st.button("Resetar logins e senhas", key="reset_everything"):
            reset_email, reset_pass = reset_all_users()
            st.success("Base de usuários limpa com sucesso.")
            if reset_email and reset_pass:
                st.info(
                    f"Admin padrão recriado:\nEmail: **{reset_email}**\nSenha: **{reset_pass}**"
                )

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
        new_phone = st.text_input("Telefone (para SMS, opcional)")
        recovery_method = st.radio(
            "Método de recuperação", ["Email", "SMS", "Authenticator"], index=0
        )
        new_is_admin = st.checkbox("Usuário é administrador?")

        if st.button("Criar usuário"):
            if not new_name or not new_email or not new_pass:
                st.error("Preencha nome, e-mail e senha.")
            elif get_user_by_email(new_email):
                st.error("Já existe usuário com esse e-mail.")
            else:
                totp_secret = create_user(
                    new_name,
                    new_email,
                    new_pass,
                    new_is_admin,
                    phone=new_phone or None,
                    recovery_method=recovery_method,
                )
                st.success("Usuário criado com sucesso!")
                if recovery_method == "Authenticator" and totp_secret:
                    st.info(
                        "Configure o app autenticador do colaborador usando a chave secreta abaixo."
                    )
                    st.code(totp_secret, language="text")

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
                    clear_recovery_state(sel_email)
                    st.success(f"Senha redefinida para {sel_email}.")
        else:
            st.info("Nenhum usuário cadastrado ainda.")

    st.markdown("---")
    st.markdown("### Recuperações de acesso em andamento")
    recuperacoes = listar_recuperacoes_pendentes()
    if not recuperacoes:
        st.info("Nenhuma solicitação de recuperação ativa.")
    else:
        df_rec = pd.DataFrame(recuperacoes)
        df_rec["recovery_expires_at"] = df_rec["recovery_expires_at"].fillna("-")
        st.dataframe(df_rec)

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
