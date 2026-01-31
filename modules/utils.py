# modules/utils.py
import base64
import logging
import re

from opsdroid.message import Message  # type: ignore

_LOGGER = logging.getLogger(__name__)


class Utils:

    LOG_ENABLED = True  # Variable global en Utils para habilitar/deshabilitar el log

    def __init__(self, config):
        self.web_service_url = config.get("web_service_url")
        self.dns_default = config.get("dns_default")
        self.token = config.get("token")

    @staticmethod
    def log_info(message, logger=_LOGGER):
        """
        Función para registrar mensajes de información si el logging está habilitado.
        """
        if Utils.LOG_ENABLED:
            logger.info(str(message))

    @staticmethod
    def validar_cadena(cadena):
        """
        Valida si la cadena contiene solo caracteres alfabéticos.
        """
        return cadena.isalpha()

    @staticmethod
    def validar_cadena_permiso(cadena):
        """
        Valida si la cadena contiene solo caracteres alfabéticos y guiones bajos.
        """
        return bool(re.match(r"^[a-zA-Z_]+$", cadena))

    @staticmethod
    def is_admin(data, user):
        """
        Verifica si un usuario es administrador.
        """
        return user in data.get("admin", {})

    @staticmethod
    def is_member(data, user):
        return user in data.get("miembros", {})

    @staticmethod
    def is_creator(data, user, rol=None):
        if rol:
            return user in data.get("creadores", {}).get(rol, [])
        else:
            for roles in data.get("creadores", {}):
                if user in data["creadores"][roles]:
                    return True
            return False

    @staticmethod
    def is_nivel(data, rol):
        return rol in data.get("nivel", {})

    @staticmethod
    def decode_base64(base64_string: str) -> str:
        """Decodifica un mensaje codificado en base64."""
        return base64.b64decode(base64_string.encode("utf-8")).decode("utf-8")

    @staticmethod
    def encode_base64(plain_string: str) -> str:
        """Codifica un mensaje en base64."""
        return base64.b64encode(plain_string.encode("utf-8")).decode("utf-8")

    @staticmethod
    def clean_value(raw_value: str) -> str:
        """Limpia un valor eliminando espacios y saltos de línea."""
        return re.sub(r"\s+", "", raw_value).strip()

    @staticmethod
    def is_websocket(message: Message) -> bool:
        """Verifica si el conector del mensaje es 'websocketmod'.
        bool: True si el conector es 'websocketmod', False en caso contrario.
        """
        return message.connector.name == "websocketmod"

    @staticmethod
    def is_matrix(message: Message) -> bool:
        """Verifica si el conector del mensaje es 'matrix'.
        bool: True si el conector es 'matrix', False en caso contrario.
        """
        return message.connector.name == "matrixmod"

    @staticmethod
    def is_telegram(message: Message) -> bool:
        """Verifica si el conector del mensaje es 'telegram'.
        bool: True si el conector es 'telegram', False en caso contrario.
        """
        return message.connector.name == "telegrampost"

    # @staticmethod
    # async def response(event, response_str: str):
    #     """Genera una respuesta codificada si el evento es websocket, o en texto plano de otro modo."""
    #     if Utils.is_websocket(event):
    #         encoded_value = Utils.encode_base64(response_str)
    #         await event.respond(encoded_value)
    #         Utils.log_info(response_str)
    #     else:
    #         await event.respond(response_str)
    #         Utils.log_info(response_str)


    @staticmethod
    async def response(event, response_str: str):
        """Genera una respuesta codificada si el evento es websocket, o en texto plano de otro modo."""
        if Utils.is_websocket(event):
            encoded_value = Utils.encode_base64(response_str)
            await event.respond(encoded_value)
            Utils.log_info(response_str)
        else:
            if Utils.is_telegram(event):
                TELEGRAM_MAX_LENGTH = 4096
                if len(response_str) > TELEGRAM_MAX_LENGTH:
                    truncated_msg = response_str[:TELEGRAM_MAX_LENGTH - 50]
                    truncated_msg += "\n[Mensaje truncado debido a límite de caracteres]"
                    await event.respond(truncated_msg)
                    Utils.log_info("Mensaje original truncado por exceder 4096 caracteres")
                    Utils.log_info(response_str)
                else:
                    await event.respond(response_str)
                    Utils.log_info(response_str)
            else:
                await event.respond(response_str)
                Utils.log_info(response_str)


    

    @staticmethod
    def build_pattern(command):
        """Construye un patrón regex para el comando dado."""
        command_pattern = rf"{command}"  # Comando que pasa a la función
        value_pattern = r"(( )(?P<value>.+))?$"  # Patrón para capturar el valor después del comando
        pattern = rf"^!{command_pattern}{value_pattern}"  # Patrón final
        return pattern

    @staticmethod
    def validar_tg_id(tg_id):
        import re

        patron = r"^\d{1,10}$"
        return bool(re.match(patron, tg_id))

    @staticmethod
    def validar_cadena_numerica(tg_id):
        import re

        patron = r"^\d{1,10}$"
        return bool(re.match(patron, tg_id))

    def get_userid(event):
        import re

        user_id = event.user_id
        if Utils.is_matrix(event):
            _LOGGER.info(f"logged in with user: {user_id}")
            _LOGGER.info(f"connector name: {event.connector.name}")
            x = re.search(r"@([^:]+):", user_id)
            user_id = x.group(1)
            _LOGGER.info(f"user: {user_id}")
            return str(user_id)

        if Utils.is_websocket(event):
            _LOGGER.info(f"logged in with user: {event.user}")
            _LOGGER.info(f"connector name: {event.connector.name}")
            _LOGGER.info(f"user: {user_id}")
            return str(event.user)

        if Utils.is_telegram(event):
            _LOGGER.info(f"logged in with user: {event.user}")
            _LOGGER.info(f"connector name: {event.connector.name}")
            _LOGGER.info(f"user: {event.user_id}")
            return str(event.user_id)

    def normalizar_texto(texto):
        import unicodedata

        # Convertir a minúsculas y eliminar acentos
        return unicodedata.normalize("NFKD", texto).encode("ASCII", "ignore").decode("ASCII").lower()

    @staticmethod
    def listar_roles(data):
        """
        Devuelve una cadena de roles disponibles en el sistema, separados por comas.
        """
        roles = data.get("roles", [])
        return ", ".join(roles) if roles else "No hay roles disponibles."
