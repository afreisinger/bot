import json
import logging
import sys

from opsdroid.events import Image
from opsdroid.matchers import match_event, match_regex  # type: ignore
from opsdroid.message import Message  # type: ignore
from opsdroid.skill import Skill  # type: ignore
from voluptuous import Required  # type: ignore
from opsdroid.skill import Skill
from opsdroid.matchers import match_catchall

sys.path.append("/modules")
from acl import Permisos
from utils import Utils

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    Required("dns_default"): str,
    Required("token"): str,
    Required("urls"): str,  # lista de url separadas por comas
    "enable": str,
}


from opsdroid.skill import Skill
from opsdroid.matchers import match_catchall
import traceback

# class ollama(Skill):
#     from utils import Utils 
#     def __init__(self, opsdroid, config):
#         import sys
#         super().__init__(opsdroid, config)
#         sys.path.append("/modules")
#         _LOGGER.debug("Loaded Ollama")
#         #self.enable = config.get("enable","False")
#         self.enable = str(config.get("enable", "false")).lower() == "true"
#         _LOGGER.debug(f"self.enable:  {self.enable}")

#     def get_connector_name(self, event):
#             """Obtiene el nombre del connector"""
#             return event.connector.name
        
#     def get_user(self, event):
#             """Obtiene el user_id de cualquier canal"""
#             return event.user_id
        
        
#     async def load_data(self, event):
#             """Carga los datos de grupos desde el backend de memoria"""
#             data_json = await self.opsdroid.memory.get("grupos", "{}")
#             if data_json is None or data_json == "{}":
#                 Utils.log_info("Error al cargar los datos. Verificar fuente de datos")
#                 return None
#             try:
#                 return json.loads(data_json)
#             except json.JSONDecodeError:
#                 Utils.log_info("Error al procesar los datos. AsegÃºrese de que el formato sea correcto.")
#                 return None
            
        
#     async def load_authorized_users(self, event):
#             """Carga los usuarios autorizados desde Redis usando Opsdroid memory backend."""
#             authorized_users = {}
#             data = await self.load_data(event)  # Cargar los datos desde la memoria

#             if "telegram" not in data:  # Verificar si la secciÃ³n de Telegram existe
#                 _LOGGER.warning("No se encontrÃ³ la secciÃ³n de Telegram en los datos.")
#                 return authorized_users  # Retornar un diccionario vacÃ­o si no hay usuarios

#             telegram_users = data["telegram"]  # Obtener los usuarios de Telegram

#             for user_id, user_info in telegram_users.items():  # Procesar los usuarios de Telegram
#                 username = user_info.get("username")
#                 if username:
#                     authorized_users[int(user_id)] = username  # Mapear el user_id como int y el username

#             _LOGGER.info(f"Usuarios autorizados: {authorized_users}")
#             return authorized_users
        
        
#     async def pre_process(self, event):
#             """Realiza validaciones segun el origen del mensaje"""

#             connector_name = self.get_connector_name(event)
#             if connector_name == "websocketmod":
#                 return "websocketmod", True

#             elif connector_name == "mailconnector":
#                 return "mailconnector", True

#             elif connector_name == "matrixmod":
#                 return "matrixmod", True

#             elif connector_name == "telegrampost":
#                 user_id = self.get_user(event)
#                 if user_id:

#                     self.authorized_users = await self.load_authorized_users(event)

#                     if user_id in self.authorized_users:
#                         _LOGGER.info(f"user_id {user_id} autorizado.")
#                         _LOGGER.info(f"username: {self.authorized_users[user_id]}")
#                         return "telegrampost", True  # Usuario autorizado, continuar
#                     else:
#                         _LOGGER.info(f"user_id {user_id} no autorizado.")
#                         return "telegrampost", False  # Usuario no autorizado, detener
#                 else:
#                     _LOGGER.info("No se pudo obtener el ID de usuario.")
#                     return "telegrampost", False  # Error al obtener el ID, detener
#             return connector_name, True
               
        
#     @match_catchall(messages_only=True)
#     async def ollama(self, event):
#             _LOGGER.debug("ollama entry")
#             import requests
            
#             # if self.enable != "True":
#             #     _LOGGER.debug(("ollama enable: '%s'"), self.enable)
#             #     return
            
#             if not self.enable:
#                 _LOGGER.debug(("ollama enable: '%s'"), self.enable)
#                 return
            
            
            
#             try:
             
#                 text = str(event.text)
#                 #user_id = str(event.user_id)
#                 user_id = str(Utils.get_userid(event))
#                 joined_members = 100
#                 connector_name = str(event.connector.name)
#                 room = str(event.target)
#                 if connector_name == "matrixmod":
#                     conn = event.connector
#                     jm = await conn.connection.joined_members(room)
#                     _LOGGER.info(f"Room {room} has {len(jm.members)} joined members.")
#                     joined_members = len(jm.members)
#                 elif connector_name == "mailconnector":
#                     joined_members = 1
#                 elif connector_name == "websocketmod":
#                     joined_members = 1
#                 elif connector_name == "telegrampost":
#                     if room[0] == "-":
#                         _LOGGER.info(f"Room {room} is a telegram group. Setting joined_members to 100.")
#                         joined_members = 100
#                     else:
#                         _LOGGER.info(f"Room {room} is NOT a telegram group. Setting joined_members to 2.")
#                         joined_members = 2


#                 if joined_members > 2:
#                     _LOGGER.info("joined_members > 2. exit.")
#                     return

#                 room = str(event.target)
#                 data_input = {"userId": user_id, "query": text}
#                 headers = {"Content-Type" : "application/json"}
#                 url = "http://10.30.154.149:8000"
#                 proxies = {
#                             "http": "",
#                             "https": "",
#                             }
                
#                 #user_id = str(Utils.get_userid(event))
#                 data = await self.load_data(event)
                
#                 if data is None:
#                     _LOGGER.error("No se pudo cargar la estructura de datos.")
#                     return
                
#                 connector_type, continue_execution = await self.pre_process(event)
#                 if not continue_execution:  # usuario de telegram no autorizado
#                     _LOGGER.info(f"connector_type: {connector_type} continue_execution: {continue_execution}")
#                     return

                
#                 req = requests.post(url=url,headers=headers, json=data_input, verify=False,proxies=proxies)
#                 _LOGGER.debug(url)
#                 _LOGGER.debug(data_input)
                
#                 _LOGGER.debug(req)
#                 _LOGGER.debug(req.text)
#                 j = req.json()
#                 if "detail" in j:
#                     ret = j["detail"]
#                 else:
#                     ret = j["response"]
#                 _LOGGER.debug("ollama response ret: " + str(ret))
#                 if connector_name == "matrixmod":
#                     await event.respond(f"<pre>\n" + ret + "</pre>")
#                 elif connector_name == "mailconnector":
#                     await event.respond(f"{ret}")
#                 elif connector_name == "telegrampost":
#                     await event.respond(f"{ret}")
#                 elif connector_name == "websocketmod":
#                     retb64 = Utils.encode_base64(str(ret))
#                     await event.respond(f"{retb64}")
#                 else:
#                     _LOGGER.info(f"{connector_name} Not implemented")


#             except ValueError as e:
#                 # Loguear el error y responder al usuario
#                 Utils.log_info(f"Error: {str(e)}")
#                 await Utils.response(event, str(e))
#                 traceback.print_exc()

#             except KeyError as e:
#                 Utils.log_info(f"KeyError: Missing key in data: {str(e)}")  # Registro en los logs
#                 traceback.print_exc()  # Mostrar el traceback del error para debug
#                 await Utils.response(event, "Error de clave faltante en los datos.")

#             except Exception as e:
#                 Utils.log_info(f"Unexpected error: {str(e)}")  # Registro en los logs
#                 traceback.print_exc()  # Mostrar el traceback del error para debug
#                 await Utils.response(event, "OcurriÃ³ un error inesperado.")


class devops(Skill):

    def __init__(self, opsdroid, config):
        import sys

        super().__init__(opsdroid, config)

        sys.path.append("/modules")

        self.dns_default = config.get("dns_default")
        self.token = config.get("token")
        self.urls = config.get("urls").split(",")  # lista de urls

    async def load_data(self):
        """Carga los datos de grupos desde el backend de memoria."""
        try:
            grupos_json = await self.opsdroid.memory.get("grupos", "{}")
            _LOGGER.info(f"JSON de grupos desde memoria: {grupos_json}")
            return json.loads(grupos_json)
        except Exception as e:
            _LOGGER.error(f"Error al cargar datos desde memoria: {e}")
            return {}  # Retornar un diccionario vacÃ­o en caso de error

    async def load_authorized_users(self, event):
        """Carga los usuarios autorizados desde Redis usando Opsdroid memory backend."""
        authorized_users = {}
        grupos = await self.load_data()  # Cargar los datos desde la memoria
        # _LOGGER.info(f"Datos cargados desde Redis: {grupos}")

        if "telegram" not in grupos:  # Verificar si la secciÃ³n de Telegram existe
            _LOGGER.warning("No se encontro la seccion de Telegram en los datos.")
            return authorized_users  # Retornar un diccionario vacÃ­o si no hay usuarios

        telegram_users = grupos["telegram"]  # Obtener los usuarios de Telegram
        # _LOGGER.info(f"Usuarios de Telegram cargados: {telegram_users}")

        for user_id, user_info in telegram_users.items():  # Procesar los usuarios de Telegram
            username = user_info.get("username")
            if username:
                authorized_users[int(user_id)] = username  # Mapear el user_id como int y el username
                # _LOGGER.info(f"Usuario autorizado aÃ±adido: {user_id} - {user_info['username']}")

        _LOGGER.info(f"Usuarios autorizados: {authorized_users}")
        return authorized_users

    def get_user(self, message):
        return message.user_id

    def get_connector_name(self, message):
        return message.connector.name

    async def pre_process(self, message):
        """Realiza validaciones segun el origen del mensaje"""

        connector_name = self.get_connector_name(message)
        if Utils.is_websocket(message):
            return "websocketmod", True

        elif Utils.is_telegram(message):
            user_id = self.get_user(message)
            if user_id:

                self.authorized_users = await self.load_authorized_users(message)

                if user_id in self.authorized_users:
                    _LOGGER.info(f"username: {self.authorized_users[user_id]}")
                    return "telegrampost", True  # Usuario autorizado, continuar
                else:
                    # await message.respond("Usuario no autorizado.")    #se quita notificaciÃ³n al usuario
                    _LOGGER.info(f"user_id {user_id} no autorizado.")
                    return "telegrampost", False  # Usuario no autorizado, detener
            else:
                # await message.respond("No se pudo obtener el ID de usuario.")
                _LOGGER.info(f"No se pudo obtener el ID de usuario.")
                return "telegrampost", False  # Error al obtener el ID, detener
        return connector_name, True

    def handle_request(self, message, command, value, headers=None, params=None, proxies=None, verify=False):
        import requests
        from utils import Utils

        """Maneja una solicitud HTTP GET iterando, decodifica los mensajes base64 de la respuesta
        y devuelve los resultados. Si ocurre un error, codifica el mensaje de error en base64.
        Si el comando no existe, lo indica"""

        requests.packages.urllib3.disable_warnings()
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":HIGH:!DH:!aNULL"

        for url in self.urls:  # iteracciÃ³n con los contratos pasados por .env

            full_url = self.construct_url(url, command.lower(), value)  # endopoint+comando+valor

            try:
                response = requests.get(full_url, headers=headers, params=params, proxies=proxies, verify=verify)

                if response.status_code != 290:  # endponit correcto
                    """comando existe en el endpoint"""
                    response.raise_for_status()
                    response_json = response.json()
                    tipo = "text"
                    if "type" in response.headers:
                        _LOGGER.info(f"Tengo header type. [{response.headers['type']}]")
                        message.type = response.headers["type"]
                        tipo = "image"
                        stdout = response_json.get("stdout", "")  # no decodifico es binario!
                    else:
                        stdout = Utils.decode_base64(response_json.get("stdout", ""))  # decodifica base64
                    stderr = Utils.decode_base64(response_json.get("stderr", ""))
                    msg = Utils.decode_base64(response_json.get("msg", ""))

                    return self.format_response_based_on_connector(
                        message, stdout, stderr, msg, response_json,tipo
                    )  # devoluciÃ³n en funciÃ³n del tipo de conector

                _LOGGER.info(
                    f"Request failed with status 290 for URL: {full_url}, trying next URL."
                )  # itera con el prÃ³xima url.

            except requests.RequestException as e:

                _LOGGER.info(f"HTTP Request failed for URL {full_url}: {e}")
                if Utils.is_websocket(message):
                    return "", Utils.encode_base64(str(e)), ""
                else:
                    return "", str(e), ""


        _LOGGER.info(f"Command {command}, not found")
        if Utils.is_websocket(message):
            return (
                "",
                "", #Utils.encode_base64(f"Command {command} not found"), (idem)
                "",
            )  # si el comando no existe, visualiza. Tendria que ser en funcion del conector ?
        else:
            return (
                "",
                "", #f"Command {command} not found", (Se modifica para que no visualice)
                "",
            )  # si el comando no existe, visualiza. Tendria que ser en funcion del conector ?

    def format_response_based_on_connector(self, message, stdout, stderr, msg, response_json, tipo):
        from utils import Utils

        """ Devuelve la respuesta adecuada dependiendo del conector. """
        
        if Utils.is_websocket(message) and tipo not in ["image","file","sound", "video"]:
            return response_json.get("stdout", ""), response_json.get("stderr", ""), response_json.get("msg", "")  # Ba
        elif Utils.is_matrix(message) and tipo not in ["image","file", "sound", "video"]:
            stdout = "<pre>\n" + stdout + "</pre>"
            return stdout, stderr, msg  # plano
        elif Utils.is_telegram(message) and tipo not in ["image","file", "sound", "video"]:
            #stdout = "```bash\n" + stdout +"\n```"
            return stdout, stderr, msg  # plano
        else:
            return stdout, stderr, msg  # plano

    def format_response(self, stdout, stderr, msg):
        """Formatea una respuesta combinando stdout, stderr, y un mensaje adicional."""
        response_parts = []

        if msg:
            response_parts.append(msg)
        if stdout:
            response_parts.append(stdout)
        if stderr:
            response_parts.append(stderr)

        return "\n".join(response_parts).strip()

    def construct_url(self, url, command: str, value: str) -> str:
        from utils import Utils

        """ Construye la URL para la solicitud en funciÃ³n del comando y valor proporcionados. """

        if command == "dig":
            parts = value.split()
            host = parts[0] if parts else ""
            nameserver = parts[1] if len(parts) > 1 else self.dns_default
            return f"{url}/{command}/{nameserver}/{host}"

        elif command == "citrix_ver_granja":
            parts = value.split()
            balanceador = parts[0] if parts else ""
            granja = parts[1]
            return f"{url}/{command}/{balanceador}/{granja}"

        else:
            value = Utils.clean_value(value)
            return f"{url}/{command}/{value}"

    async def send_request(self, message, command: str, value: str):
        import base64
        headers = {"Accept": "application/jbase64", "Authorization": f"Bearer {self.token}"}
        params = {}
        proxies = {}
        verify = False

        stdout, stderr, msg = self.handle_request(
            message, command, value, headers=headers, params=params, proxies=proxies, verify=verify
        )
        if hasattr(message,"type") and message.type == "image":
            _LOGGER.info(f"Sending bonita_imagen to {message.target} on {message.connector.name}")
            await self.opsdroid.send(
                Image(
                    connector=message.connector, target=message.target, file_bytes=base64.b64decode(stdout)
                )
            )
        else:
            response_message = self.format_response(stdout, stderr, msg)
            _LOGGER.info(f"Sending {response_message} to {message.target} on {message.connector.name}")
            await message.respond(response_message)

    @match_regex(r"ping")
    async def ping_pong(self, message):
        from utils import Utils

        connector_type, continue_execution = await self.pre_process(message)  # preproceso
        if not continue_execution:  # usuario de telegram no autorizado o error al obtener el id_user
            return
        if connector_type == "websocketmod":
            await message.respond(Utils.encode_base64("pong"))  # Codificar la respuesta en Base64 para WebSocket
        else:
            await message.respond("pong")  # Responder normalmente para otros conectores

    #  https://gitlab.cloudint.afip.gob.ar/depsst/opsdroid/-/blob/master/opsdroid_custom/skills/skill-webhook/__init__.py
    # @match_regex(r"cargar_imagen") ####ACACACACACA
    async def handle_image_event(self, event):
        import base64

        _LOGGER.info("ACA")
        _LOGGER.info(f"event: {event}")
        if hasattr(event, "headers") and event.headers.get("image"):
            image_data = event.headers.get("image")
            await event.respond("Imagen recibida y procesada.")
            self.opsdroid.send(
                Image(
                    text="Imagen", connector=event.connector, target=event.target, file_bytes=base64.decode(image_data)
                )
            )
        else:
            await event.respond("No se recibio una imagen.")

    command_pattern = r"(?P<command>\w+)"
    value_pattern = rf"(( )(?P<value>.+))?$"
    pattern = rf"^! {command_pattern}{value_pattern}"

    @match_regex(r"vars")
    async def vars(self, message):
        _LOGGER.info(dir(message))  # Ver todos los atributos del mensaje
        _LOGGER.info(vars(message))  # Ver el contenido del mensaje completo

    @match_regex(pattern)
    async def handle_command(self, message):
        command = message.regex.group("command")
        value = message.regex.group("value") if message.regex.group("value") else ""
        connector_type, continue_execution = await self.pre_process(message)  # preproceso
        if not continue_execution:  # usuario de telegram no autorizado o error al obtener el id_user
            return
        if connector_type == "websocketmod" or connector_type == "telegrampost" or connector_type == "mailconnector" or connector_type == "matrixmod":
            if command == "help" or command == "ayuda" or command == "manual" :
                await self.mostrar_ayuda(message)
                return
            await self.send_request(message, command, value)

    @match_event(Image)
    async def loudimage(self, event):
        await event.respond(Message("THAT'S A PRETTY PICTURE"))



    def get_username_by_id(self, data, tg_id):
        """Devuelve el username asociado al tg_id"""
        return data.get("telegram", {}).get(str(tg_id), {}).get("username", None)

            

    async def mostrar_ayuda(self, event):
        """
        Muestra la ayuda para un rol específico o todos los roles si no se especifica uno.
        """
        """
        help_option = event.regex.group("help")
        if help_option:
            help_message = (
                "Descripción: Muestra la ayuda asociada a un rol específico o a todos los roles.\n"
                "Uso: !mostrar_ayuda <rol>\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !mostrar_ayuda DEIRET\n"
                "            !mostrar_ayuda\n"
            )
            await Utils.response(event, help_message)
            return
        """
        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data()

            # Verifica si los datos se han cargado correctamente
            if data is None:
                raise ValueError("No se pudo cargar la estructura de datos.")

            connector_type, continue_execution = await self.pre_process(event)
            if not continue_execution:  # usuario de telegram no autorizado
                raise ValueError(f"connector_type: {connector_type} continue_execution: {continue_execution}")

            if connector_type == "websocketmod":
                if not Utils.validar_cadena(user_id):
                    raise ValueError(f'El nombre de usuario "{user_id}" posee caracteres inválidos.')

            # con tg_id que viene por el conector, se obtiene el username
            elif connector_type == "telegrampost":
                tg_id = user_id
                user_id = self.get_username_by_id(data, tg_id)

            user_id = user_id.lower()

            """
            rol = event.regex.group("rol")
            if rol:
                # Valida el rol
                if not Utils.validar_cadena(rol):
                    raise ValueError('El rol "{rol}" posee caracteres inválidos.')

                rol = rol.upper()

                # Verifica si el rol existe en los datos
                if rol not in data.get("roles", []):
                    raise ValueError(f'El rol "{rol}" no existe en el sistema.')

                # Muestra la ayuda específica para el rol
                mensaje_ayuda = data["ayuda"].get(rol)
                if mensaje_ayuda:
                    await Utils.response(event, f"Ayuda para {rol}: {mensaje_ayuda}")
                else:
                    await Utils.response(event, f"No se encontró ayuda para el rol '{rol}'.")
            else:
            """
                # Muestra la ayuda de todos los roles
            roles_usuario = data["miembros"][user_id]
            todas_ayudas = []
            for rol in roles_usuario:
                todas_ayudas.append("ROL " + str(rol) + " " + str(data["ayuda"][rol]))
            #todas_ayudas = [f"{rol}: {mensaje}" for rol, mensaje in data.get("ayuda", {}).items()]
            if len(todas_ayudas) > 0:
                await Utils.response(
                      event,
                      "Ayuda para todos los roles del usuario:\n" + "\n".join(todas_ayudas),
                )
            else:
                await Utils.response(
                        event,
                        "No hay mensajes de ayuda definidos para ningún rol.",
                    )

        except ValueError as e:
            # Loguear el error y responder al usuario
            Utils.log_info(f"Error: {str(e)}")
            await Utils.response(event, str(e))
            traceback.print_exc()

        except KeyError as e:
            Utils.log_info(f"KeyError: Missing key in data: {str(e)}")  # Registro en los logs
            traceback.print_exc()  # Mostrar el traceback del error para debug
            await Utils.response(event, "Error de clave faltante en los datos.")

        except Exception as e:
            Utils.log_info(f"Unexpected error: {str(e)}")  # Registro en los logs
            traceback.print_exc()  # Mostrar el traceback del error para debug
            await Utils.response(event, "Ocurrió un error inesperado.")



