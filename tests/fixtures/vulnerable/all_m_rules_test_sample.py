import importlib
import ssl


def trigger_m_rules(module_name, user_id):
    __import__(module_name)
    importlib.import_module(module_name)

    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx2.verify_mode = ssl.CERT_NONE
