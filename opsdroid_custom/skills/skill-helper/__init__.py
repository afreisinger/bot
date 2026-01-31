import json
import logging
import traceback
from datetime import datetime, timedelta

from opsdroid.events import Message  # type: ignore
from opsdroid.matchers import match_regex  # type: ignore
from opsdroid.skill import Skill  # type: ignore
from voluptuous import Required  # type: ignore

_LOGGER = logging.getLogger(__name__)


CONFIG_SCHEMA = {Required("admin_users"): str}  # cadena de usuarios separadas por comas
import sys

if "/modules" not in sys.path:
    sys.path.append("/modules")
from acl import Permisos
from utils import Utils

# Utils.disable_logger

# para ingresar el nombre de la funcion en lugar del valor
PERMISOS_MAPA = {
    "AGREGAR_FUNCION": Permisos.AGREGAR_FUNCION.value,  # PUEDE AGREGAR NUEVA FUNCION A GRUPO AL CUAL PERTENECE
    "BORRAR_FUNCION": Permisos.BORRAR_FUNCION.value,  # PUEDE BORRAR FUNCION DE GRUPO AL CUAL PERTENECE
    "AGREGAR_USUARIO": Permisos.AGREGAR_USUARIO.value,  # PUEDE AGREGAR NUEVO USUARIO A GRUPO AL CUAL PERTENECE
    "BORRAR_USUARIO": Permisos.BORRAR_USUARIO.value,  # PUEDE BORRAR USUARIO DE GRUPO AL CUAL PERTENECE
    "ADMIN_GRUPO": Permisos.ADMIN_GRUPO.value,  # PUEDE MODIFICAR PERMISOS A OTRO USUARIO DE GRUPO AL CUAL PERTENECE
    "AGREGAR_GRUPO": Permisos.AGREGAR_GRUPO.value,  # PUEDE CREAR NUEVOS GRUPOS
    "BORRAR_GRUPO": Permisos.BORRAR_GRUPO.value,  # PUEDE BORRAR GRUPOS QUE HAYA CREADO
    "ADMIN_GLOBAL": Permisos.ADMIN_GLOBAL.value,  # TIENE TODOS LOS PERMISOS. NO SE LE PUEDE SACAR POR OTRO USUARIO
}


class HelperSkill(Skill):

    def __init__(self, opsdroid, config):
        super(HelperSkill, self).__init__(opsdroid, config)
        import sys

        sys.path.append("/modules")
        self.admin_users = [user.strip() for user in config.get("admin_users", "").split(",")]  # cadena to lista
        self.lock_key = "opsdroid:mutex"
        self.help_messages = {}

    async def load_data(self, event):
        """Carga los datos de grupos desde el backend de memoria"""
        data_json = await self.opsdroid.memory.get("grupos", "{}")
        if data_json is None or data_json == "{}":
            Utils.log_info("Error al cargar los datos. Verificar fuente de datos")
            return None
        try:
            return json.loads(data_json)
        except json.JSONDecodeError:
            Utils.log_info("Error al procesar los datos. Asegúrese de que el formato sea correcto.")
            return None

    async def save_data(self, data, event):
        """Guarda los datos de grupos en el backend de memoria"""
        if await self.acquire_lock():
            try:
                await self.opsdroid.memory.put("grupos", json.dumps(data))
            finally:
                await self.release_lock()
        else:
            await Utils.response(event, "Recurso ocupado")

    async def acquire_lock(self, timeout=5):
        """Adquirir un mutex usando Opsdroid Memory."""
        lock_data = await self.opsdroid.memory.get(self.lock_key)

        if lock_data is None:  # No hay lock existente
            expiration_time = datetime.utcnow() + timedelta(seconds=timeout)
            await self.opsdroid.memory.put(self.lock_key, {"expires_at": expiration_time.isoformat()})
            return True
        else:
            expires_at = datetime.fromisoformat(lock_data["expires_at"])  # Verificar si el lock ha expirado
            if datetime.utcnow() > expires_at:  # Lock expirado, adquirir nuevo lock
                await self.opsdroid.memory.delete(self.lock_key)
                expiration_time = datetime.utcnow() + timedelta(seconds=timeout)
                await self.opsdroid.memory.put(self.lock_key, {"expires_at": expiration_time.isoformat()})
                return True

    async def release_lock(self):
        """Liberar el mutex."""
        await self.opsdroid.memory.delete(self.lock_key)

    def get_user(self, event):
        """Obtiene el user_id de cualquier canal"""
        return event.user_id

    def get_connector_name(self, event):
        """Obtiene el nombre del connector"""
        return event.connector.name

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

    async def load_authorized_users(self, event):
        """Carga los usuarios autorizados desde Redis usando Opsdroid memory backend."""
        authorized_users = {}
        data = await self.load_data(event)  # Cargar los datos desde la memoria

        if "telegram" not in data:  # Verificar si la sección de Telegram existe
            _LOGGER.warning("No se encontró la sección de Telegram en los datos.")
            return authorized_users  # Retornar un diccionario vacío si no hay usuarios

        telegram_users = data["telegram"]  # Obtener los usuarios de Telegram

        for user_id, user_info in telegram_users.items():  # Procesar los usuarios de Telegram
            username = user_info.get("username")
            if username:
                authorized_users[int(user_id)] = username  # Mapear el user_id como int y el username

        _LOGGER.info(f"Usuarios autorizados: {authorized_users}")
        return authorized_users

    def obtener_roles_usuario(self, data, usuario):
        """Obtiene roles de usuario"""
        return data["miembros"].get(usuario, [])

    def get_username_by_id(self, data, tg_id):
        """Devuelve el username asociado al tg_id"""
        return data.get("telegram", {}).get(str(tg_id), {}).get("username", None)


    @match_regex(r"^_inicializar_acl(?: (?P<json_file>.+))?$")
    async def init_acl(self, event):
        """Inicializa el ACL desde un archivo JSON o vacío si no se proporciona uno. Solo admin"""
        import json
        import re

        # Estructura de ACL vacía o base
        grupos_default = {
            "admin": self.admin_users,  # administradores cargados del atributo de instancia
            "roles": [],
            "creadores": {},
            "funciones": {},
            "miembros": {},
            "ayuda": {},
            "nivel": {"__global__": []},
            "telegram": {},
        }

        userid = event.user

        # if userid not in grupos_default["admin"]:
        #     await Utils.response(event, f'Acceso denegado. {userid} no tiene permiso para ejecutar este comando.')
        #     return

        match = re.match(
            r"^_inicializar_acl(?: (?P<json_file>.+))?$", event.text
        )  # Obtengo el nombre del archivo JSON del evento (si se especifica)
        json_file = match.group("json_file") if match else None

        if json_file:  # cargo los datos desde el archivo si se proporciona
            try:
                with open(json_file, "r") as file:
                    grupos = json.load(file)
                    await Utils.response(event, f"ACL cargado desde {json_file}.")
            except FileNotFoundError:
                await Utils.response(event, f"Archivo {json_file} no encontrado. Inicializando ACL vacío.")
                grupos = grupos_default
            except json.JSONDecodeError:
                await Utils.response(event, f"Error en el formato del archivo {json_file}. Inicializando ACL vacío.")
                grupos = grupos_default
        else:

            grupos = grupos_default  # Si no se proporciona un archivo JSON, inicializo con los valores predeterminados
            await Utils.response(event, "Inicializando ACL vacío.")

        # if userid not in grupos["admin"]:   # Verificar si el usuario está en el grupo admin
        #     await Utils.response(event, f'Acceso denegado. {userid} no tiene permiso para ejecutar este comando.')
        #     return

        await self.save_data(grupos, event)  # Guardo los datos de ACL (ya sea vacíos o cargados)
        await Utils.response(event, "Datos de ACL inicializados.")  # Confirmación de la inicialización

    @match_regex(r"_verificar_permisos\s*(?P<usuario>\w+)?")
    async def verificar_permiso(self, event):
        """
        Verifica el nivel de permiso de un usuario en todos los grupos a los que pertenece, siempre que el usuario que ejecute el comando tenga los permisos adecuados.
        """

        usuario = (
            event.regex.group("usuario") or event.user
        )  # Si no se ingresa un usuario, usa el que ejecuta el comando
        grupos = await self.load_data(event)  # Cargar los grupos y sus niveles de permisos
        permisos_usuario = Permisos.permisos(event.user, grupos)

        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value

        # Verificar si el usuario existe en algún grupo
        if usuario not in grupos["miembros"]:
            await Utils.response(event, f'El usuario "{usuario}" no existe en ningún grupo.')
            return

        # Listar los grupos a los que pertenece el usuario
        grupos_usuario = grupos["miembros"].get(usuario, [])

        if not grupos_usuario:
            await Utils.response(event, f'El usuario "{usuario}" no pertenece a ningún grupo.')
            return

        # Informar los grupos a los que pertenece el usuario
        await Utils.response(
            event, f'El usuario "{usuario}" pertenece a los siguientes grupos: {", ".join(grupos_usuario)}.'
        )

        # Verificar permisos del usuario en cada grupo
        for grupo in grupos_usuario:
            nivel_actual = grupos["nivel"].get(grupo, {}).get(usuario, 0)
            nivel_event_user = permisos_usuario.get(grupo, 0)

            # Verificar si el usuario que ejecuta el comando tiene permiso para ver los niveles de otros usuarios
            # if nivel_event_user & PERMISO_ADMIN_GRUPO or event.user in grupos["admin"]:
            permisos_actuales = Permisos.permisos_usuario(nivel_actual)
            permisos_actuales_str = ", ".join(permisos_actuales)
            await Utils.response(
                event, f'Permisos del usuario "{usuario}" en el grupo "{grupo}": {permisos_actuales_str}.'
            )
            # else:
            #     await Utils.response(event, f'Permisos insuficientes para mostrar los permisos del usuario "{usuario}" en el grupo "{grupo}".')

         # Informar si el usuario que ejecuta es administrador
    #     if is_admin_event_user:
    #         await Utils.response(event, f"El usuario que ejecuta el comando es administrador del sistema.")
    
    
    
    # @match_regex(r"_info\s*(?P<usuario>\w+)?")
    # async def info(self, event):
    #     """
    #     Verifica el nivel de permiso de un usuario en todos los grupos a los que pertenece, incluyendo el nivel global,
    #     siempre que el usuario que ejecute el comando tenga los permisos adecuados.
    #     """

    #     usuario = (
    #         event.regex.group("usuario") or event.user
    #     )  # Usa el usuario que ejecuta el comando si no se proporciona uno
    #     grupos = await self.load_data()  # Cargar los grupos y sus niveles de permisos
    #     is_admin_event_user = Utils.is_admin(event.user, self.admin_users)  # Verifica si el que ejecuta es admin

    #     # Verificar si el usuario consultado es administrador
    #     is_admin_usuario = Utils.is_admin(usuario, self.admin_users)
    #     if is_admin_usuario:
    #         await Utils.response(event, f'El usuario "{usuario}" es un administrador del sistema.')

    #     # Listar los grupos a los que pertenece el usuario
    #     grupos_usuario = grupos["miembros"].get(usuario, [])

    #     if not grupos_usuario:
    #         await Utils.response(event, f'El usuario "{usuario}" no pertenece a ningún grupo.')
    #         return

    #     # Mostrar la lista de grupos
    #     await Utils.response(
    #         event, f'El usuario "{usuario}" pertenece a los siguientes grupos: {", ".join(grupos_usuario)}.'
    #     )

    #     # Verificar permisos globales (__global__) del usuario consultado
    #     permiso_global_usuario = grupos["nivel"].get("__global__", {}).get(usuario, 0)
    #     permisos_globales = Permisos.permisos_usuario(permiso_global_usuario)
    #     permisos_globales_str = ", ".join(permisos_globales)
    #     await Utils.response(event, f'Permisos globales del usuario "{usuario}": {permisos_globales_str}.')

    #     # Verificar permisos del usuario en cada grupo
    #     for grupo in grupos_usuario:
    #         nivel_actual_usuario = (
    #             grupos["nivel"].get(grupo, {}).get(usuario, 0)
    #         )  # Nivel de permisos del usuario consultado

    #         permisos_actuales = Permisos.permisos_usuario(nivel_actual_usuario)  # Obtener permisos en formato legible
    #         permisos_actuales_str = ", ".join(permisos_actuales)
    #         await Utils.response(
    #             event, f'Permisos del usuario "{usuario}" en el grupo "{grupo}": {permisos_actuales_str}.'
    #         )

    #         # Verificar si el usuario que ejecuta el comando tiene permiso para ver los niveles de otros usuarios
    #         # if nivel_actual_event_user & PERMISO_ADMIN_GRUPO or is_admin_event_user:
    #         #     permisos_actuales = Permisos.permisos_usuario(nivel_actual_usuario)  # Obtener permisos en formato legible
    #         #     permisos_actuales_str = ', '.join(permisos_actuales)
    #         #     await Utils.response(event, f'Permisos del usuario "{usuario}" en el grupo "{grupo}": {permisos_actuales_str}.')
    #         # else:
    #         #     await Utils.response(event, f'Permisos insuficientes para mostrar los permisos del usuario "{usuario}" en el grupo "{grupo}".')

    #     # Informar si el usuario que ejecuta es administrador
    #     if is_admin_event_user:
    #         await Utils.response(event, f"El usuario que ejecuta el comando es administrador del sistema.")

    @match_regex(r"_info\s*(?P<usuario>\w+)?")
    async def info(self, event):
        """
        Verifica el nivel de permiso de un usuario en todos los grupos a los que pertenece, incluyendo el nivel global,
        siempre que el usuario que ejecute el comando tenga los permisos adecuados.
        """

        try:
            user_id = Utils.get_userid(event)
            data = await self.load_data(event)

            if data is None:
                raise ValueError("No se pudo cargar la estructura de datos.")

            connector_type, continue_execution = await self.pre_process(event)
            if not continue_execution:  # usuario de telegram no autorizado
                #raise ValueError(f"connector_type: {connector_type} continue_execution: {continue_execution}")
                _LOGGER.info(f"connector_type: {connector_type} continue_execution: {continue_execution}")
                return


            if connector_type == "websocketmod":
                if not Utils.validar_cadena(user_id):
                    raise ValueError(f'El nombre de usuario "{user_id}" posee caracteres inválidos.')


            # con tg_id que viene por el conector, se obtiene el username
            elif connector_type == "telegrampost":
                tg_id = user_id
                user_id = self.get_username_by_id(data, tg_id)

            user_id = user_id.lower()
            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            usuario = event.regex.group("usuario")
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(usuario):
                raise ValueError('El usuario "{usuario}" posee caracteres inválidos.')

            is_member = Utils.is_member(data, usuario)
            is_admin = Utils.is_admin(data, usuario)
            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{usuario}" no existe en el sistema')

            # Obtener roles del usuario que ejecuta el comando
            roles = data["miembros"].get(usuario, [])
            # await Utils.response(event, f'Roles "{roles}"')

            await Utils.response(
                event, f'El usuario "{usuario}" pertenece a los siguientes grupos: {", ".join(roles)}.'
            )
             # Informar si el usuario que ejecuta es administrador
            if is_admin:
                await Utils.response(event, f'El usuario "{usuario}" es administrador del sistema.')

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
    
    @match_regex(r"_username\s*")
    async def handle_username(self, event):
        await Utils.response(event, f"El ID del usuario es: {event.user}")
        
    @match_regex(r"_json\s*")
    async def json(self, event):
        data = await self.load_data(event)
        json_data = json.dumps(data, indent=4, ensure_ascii=False)
        await Utils.response(event, f"```\n{json_data}\n```")
