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
    #Required("dns_default"): str,
    #Required("token"): str,
    #Required("urls"): str,  # lista de url separadas por comas
    "enable": str,
}


from opsdroid.skill import Skill
from opsdroid.matchers import match_catchall
import traceback

class ollama(Skill):
    from utils import Utils 
    def __init__(self, opsdroid, config):
        import sys
        super().__init__(opsdroid, config)
        sys.path.append("/modules")
        _LOGGER.debug("Loaded Ollama")
        #self.enable = config.get("enable","False")
        self.enable = str(config.get("enable", "false")).lower() == "true"
        _LOGGER.debug(f"self.enable:  {self.enable}")

    def get_connector_name(self, event):
            """Obtiene el nombre del connector"""
            return event.connector.name
        
    def get_user(self, event):
            """Obtiene el user_id de cualquier canal"""
            return event.user_id
        
        
    async def load_data(self, event):
            """Carga los datos de grupos desde el backend de memoria"""
            data_json = await self.opsdroid.memory.get("grupos", "{}")
            if data_json is None or data_json == "{}":
                Utils.log_info("Error al cargar los datos. Verificar fuente de datos")
                return None
            try:
                return json.loads(data_json)
            except json.JSONDecodeError:
                Utils.log_info("Error al procesar los datos. AsegÃºrese de que el formato sea correcto.")
                return None
            
        
    async def load_authorized_users(self, event):
            """Carga los usuarios autorizados desde Redis usando Opsdroid memory backend."""
            authorized_users = {}
            data = await self.load_data(event)  # Cargar los datos desde la memoria

            if "telegram" not in data:  # Verificar si la secciÃ³n de Telegram existe
                _LOGGER.warning("No se encontrÃ³ la secciÃ³n de Telegram en los datos.")
                return authorized_users  # Retornar un diccionario vacÃ­o si no hay usuarios

            telegram_users = data["telegram"]  # Obtener los usuarios de Telegram

            for user_id, user_info in telegram_users.items():  # Procesar los usuarios de Telegram
                username = user_info.get("username")
                if username:
                    authorized_users[int(user_id)] = username  # Mapear el user_id como int y el username

            _LOGGER.info(f"Usuarios autorizados: {authorized_users}")
            return authorized_users
        
        
    async def pre_process(self, event):
            """Realiza validaciones segun el origen del mensaje"""

            connector_name = self.get_connector_name(event)
            if connector_name == "websocketmod":
                return "websocketmod", True

            elif connector_name == "mailconnector":
                return "mailconnector", True

            elif connector_name == "matrixmod":
                return "matrixmod", True

            elif connector_name == "telegrampost":
                user_id = self.get_user(event)
                if user_id:

                    self.authorized_users = await self.load_authorized_users(event)

                    if user_id in self.authorized_users:
                        _LOGGER.info(f"user_id {user_id} autorizado.")
                        _LOGGER.info(f"username: {self.authorized_users[user_id]}")
                        return "telegrampost", True  # Usuario autorizado, continuar
                    else:
                        _LOGGER.info(f"user_id {user_id} no autorizado.")
                        return "telegrampost", False  # Usuario no autorizado, detener
                else:
                    _LOGGER.info("No se pudo obtener el ID de usuario.")
                    return "telegrampost", False  # Error al obtener el ID, detener
            return connector_name, True
               
        
    @match_catchall(messages_only=True)
    async def ollama(self, event):
            _LOGGER.debug("ollama entry")
            import requests
            
            # if self.enable != "True":
            #     _LOGGER.debug(("ollama enable: '%s'"), self.enable)
            #     return
            
            if not self.enable:
                _LOGGER.debug(("ollama enable: '%s'"), self.enable)
                return
            
            
            
            try:
             
                text = str(event.text)
                #user_id = str(event.user_id)
                user_id = str(Utils.get_userid(event))
                joined_members = 100
                connector_name = str(event.connector.name)
                room = str(event.target)
                if connector_name == "matrixmod":
                    conn = event.connector
                    jm = await conn.connection.joined_members(room)
                    _LOGGER.info(f"Room {room} has {len(jm.members)} joined members.")
                    joined_members = len(jm.members)
                elif connector_name == "mailconnector":
                    joined_members = 1
                elif connector_name == "websocketmod":
                    joined_members = 1
                elif connector_name == "telegrampost":
                    if room[0] == "-":
                        _LOGGER.info(f"Room {room} is a telegram group. Setting joined_members to 100.")
                        joined_members = 100
                    else:
                        _LOGGER.info(f"Room {room} is NOT a telegram group. Setting joined_members to 2.")
                        joined_members = 2


                if joined_members > 2:
                    _LOGGER.info("joined_members > 2. exit.")
                    return

                room = str(event.target)
                data_input = {"userId": user_id, "query": text}
                headers = {"Content-Type" : "application/json"}
                url = "http://10.30.154.149:8000"
                proxies = {
                            "http": "",
                            "https": "",
                            }
                
                #user_id = str(Utils.get_userid(event))
                data = await self.load_data(event)
                
                if data is None:
                    _LOGGER.error("No se pudo cargar la estructura de datos.")
                    return
                
                connector_type, continue_execution = await self.pre_process(event)
                if not continue_execution:  # usuario de telegram no autorizado
                    _LOGGER.info(f"connector_type: {connector_type} continue_execution: {continue_execution}")
                    return

                
                req = requests.post(url=url,headers=headers, json=data_input, verify=False,proxies=proxies)
                _LOGGER.debug(url)
                _LOGGER.debug(data_input)
                
                _LOGGER.debug(req)
                _LOGGER.debug(req.text)
                j = req.json()
                if "detail" in j:
                    ret = j["detail"]
                else:
                    ret = j["response"]
                _LOGGER.debug("ollama response ret: " + str(ret))
                if connector_name == "matrixmod":
                    await event.respond(f"<pre>\n" + ret + "</pre>")
                elif connector_name == "mailconnector":
                    await event.respond(f"{ret}")
                elif connector_name == "telegrampost":
                    await event.respond(f"{ret}")
                elif connector_name == "websocketmod":
                    retb64 = Utils.encode_base64(str(ret))
                    await event.respond(f"{retb64}")
                else:
                    _LOGGER.info(f"{connector_name} Not implemented")


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