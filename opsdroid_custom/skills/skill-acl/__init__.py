import json
import logging
import sys
import traceback
from datetime import datetime, timedelta

from opsdroid.matchers import match_catchall, match_regex
from opsdroid.skill import Skill  # type: ignore
from voluptuous import Required  # type: ignore

_LOGGER = logging.getLogger(__name__)
LOG_ENABLED = True

CONFIG_SCHEMA = {Required("admin_users"): str}  # cadena de usuarios separadas por comas

if "/modules" not in sys.path:
    sys.path.append("/modules")
from acl import Permisos
from utils import Utils

# import exceptions

# para ingresar el nombre de la funcion en lugar del valor
PERMISOS_MAPA = {
    "AGREGAR_FUNCION": Permisos.AGREGAR_FUNCION.value,  # 1 PUEDE AGREGAR NUEVA FUNCION A GRUPO AL CUAL PERTENECE
    "BORRAR_FUNCION": Permisos.BORRAR_FUNCION.value,  # 2 PUEDE BORRAR FUNCION DE GRUPO AL CUAL PERTENECE
    "AGREGAR_USUARIO": Permisos.AGREGAR_USUARIO.value,  # 4 PUEDE AGREGAR NUEVO USUARIO A GRUPO AL CUAL PERTENECE
    "BORRAR_USUARIO": Permisos.BORRAR_USUARIO.value,  # 8 PUEDE BORRAR USUARIO DE GRUPO AL CUAL PERTENECE
    "ADMIN_GRUPO": Permisos.ADMIN_GRUPO.value,  # 16 PUEDE MODIFICAR PERMISOS A OTRO USUARIO DE GRUPO AL CUAL PERTENECE
    "AGREGAR_GRUPO": Permisos.AGREGAR_GRUPO.value,  # 32 PUEDE CREAR NUEVOS GRUPOS
    "BORRAR_GRUPO": Permisos.BORRAR_GRUPO.value,  # 64 PUEDE BORRAR GRUPOS QUE HAYA CREADO
    "ADMIN_GLOBAL": Permisos.ADMIN_GLOBAL.value,  # 128 TIENE TODOS LOS PERMISOS. NO SE LE PUEDE SACAR POR OTRO USUARIO
}


class ACLSkill(Skill):
    """
    Esta es la documentación de la clase ACLSkill.

    Métodos:
    - mi_metodo(): Describe lo que hace este método.
    """

    def __init__(self, opsdroid, config):
        super(ACLSkill, self).__init__(opsdroid, config)
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

    # @match_catchall
    # async def comando_no_valido(self, event):
    #     """
    #     Responde cuando el comando no coincide con ninguno de los patrones definidos.
    #     """
    #     await Utils.response(event, "Comando no válido. Por favor, verifique la sintaxis.")

    @match_regex(r"!agregar_funcion\s*(?P<help>--help|-h)?\s*(?P<funcion>\w+)?\s*(?P<rol>\w+)?\s*(?P<all>--all|-a)?")
    async def agregar_funcion(self, event):
        """
        Agrega un rol a una función existente.
        """

        help_option = event.regex.group("help")
        all_option = event.regex.group("all")

        if help_option:
            help_message = (
                "Descripción: Agrega una o mas roles a la función especificada.\n"
                "Uso: !agregar_funcion <funcion> [rol] [--help|-h] [--all|-a]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "            --all, -a     Agrega al usuario a todos los roles.\n"
                "Ejemplo:\n"
                "            !agregar_funcion ping DEIRET\n"
                "            !agregar_funcion ping --all\n"
                "            !agregar_funcion ping (solo administradores)"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            funcion = event.regex.group("funcion")
            if not funcion:
                raise ValueError("Debe especificar el nombre de la función o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(funcion):
                raise ValueError(f'La función "{funcion}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper() if rol else None  # Convertir a mayúsculas si es válido

            if funcion not in data["funciones"]:
                raise ValueError(f'La función "{funcion}" no existe en el sistema.')

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Obtener roles del usuario que ejecuta el comando
            roles_user_id = data["miembros"].get(user_id, [])

            # Determina qué roles agregar
            roles_a_agregar = []

            if all_option:
                roles_a_agregar = roles_user_id  # Agregar todos los roles
            elif rol:
                if rol not in data["roles"]:
                    raise ValueError(f'El rol "{rol}" no existe.')

                roles_a_agregar.append(rol)

            Utils.log_info(f"roles a agregar: {roles_a_agregar}")

            # Verificación adicional para administradores
            if not roles_a_agregar and is_admin:  # si no se paso rol y sos admin
                all_roles = data.get("roles", [])  # obtiene todos los roles existentes
                for rol in all_roles:
                    if rol not in data["funciones"][funcion]:
                        data["funciones"][funcion].append(rol)  # Añade la funcion
                        await self.save_data(data, event)
                        await Utils.response(
                            event,
                            f'Rol "{rol}" añadido a la función "{funcion}".',
                        )
                    else:
                        await Utils.response(
                            event,
                            f'La función "{funcion}" ya está asignada al rol "{rol}".',
                        )

            if not roles_a_agregar and not is_admin:
                await Utils.response(
                    event,
                    f'Debe especificar al menos un rol para la funcion "{funcion}" o "--all" para agregarlo a todos los roles.',
                )
                return

            await self.agregar_funcion_a(data, funcion, roles_a_agregar, user_id, is_admin, event)

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

    async def agregar_funcion_a(self, data, funcion, roles_a_agregar, user_id, is_admin, event):
        PERMISO_AGREGAR_FUNCION = Permisos.AGREGAR_FUNCION.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        for rol in roles_a_agregar:
            permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
            permiso = permiso_global | permiso_rol

            if (permiso & PERMISO_AGREGAR_FUNCION) or is_admin:

                if rol not in data["funciones"][funcion]:
                    data["funciones"][funcion].append(
                        rol
                    )  # Si la función existe pero el grupo no está asociado, añadirlo
                    await self.save_data(data, event)
                    mensajes.append(f'Rol "{rol}" añadido a la función "{funcion}".')
                else:
                    mensajes.append(
                        f'La función "{funcion}" ya está asignada al rol "{rol}".'
                    )  # La función ya existe y el grupo ya está asociado
            else:
                mensajes.append(f'Permisos insuficientes para agregar la función "{funcion}" al grupo "{rol}".')

        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    @match_regex(r"!borrar_funcion\s*(?P<help>--help|-h)?\s*(?P<funcion>\w+)?\s*(?P<rol>\w+)?\s*(?P<all>--all|-a)?")
    async def borrar_funcion(self, event):
        """
        Elimina un rol de una función .
        """

        help_option = event.regex.group("help")
        all_option = event.regex.group("all")

        if help_option:
            help_message = (
                "Descripción: Elimina una o mas roles de la función especificada.\n"
                "Uso: !borrar_funcion <funcion> [rol] [--help|-h] [--all|-a]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "            --all, -a     Agrega al usuario a todos los roles.\n"
                "Ejemplo:\n"
                "            !borrar_funcion ping DEIRET\n"
                "            !borrar_funcion ping --all\n"
                "            !agregar_funcion ping (solo administradores)"
            )
            if event:
                await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            funcion = event.regex.group("funcion")
            if not funcion:
                raise ValueError("Debe especificar el nombre de la función o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(funcion):
                raise ValueError(f'La función "{funcion}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper() if rol else None  # Convertir a mayúsculas si es válido

            if funcion not in data["funciones"]:
                raise ValueError(f'La función "{funcion}" no existe en el sistema.')

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Obtener roles del usuario que ejecuta el comando
            roles_user_id = data["miembros"].get(user_id, [])

            # Determina qué roles agregar
            roles_a_eliminar = []

            if all_option:
                roles_a_eliminar = roles_user_id  # Agregar todos los roles
            elif rol:
                if rol not in data["roles"]:
                    raise ValueError(f'El rol "{rol}" no existe.')

                roles_a_eliminar.append(rol)

            Utils.log_info(f"roles a eliminar: {roles_a_eliminar}")

            # Verificación adicional para administradores
            if not roles_a_eliminar and is_admin:  # si no se paso rol y sos admin
                all_roles = data.get("roles", [])  # obtiene todos los roles existentes
                for rol in all_roles:
                    if rol in data["funciones"][funcion]:
                        data["funciones"][funcion].remove(rol)  # Borral rol de la funcion
                        await self.save_data(data, event)
                        await Utils.response(
                            event,
                            f'Rol "{rol}" eliminado de la función "{funcion}".',
                        )
                    else:
                        await Utils.response(
                            event,
                            f'La función "{funcion}" no está asignada al rol "{rol}".',
                        )

            if not roles_a_eliminar and not is_admin:
                await Utils.response(
                    event,
                    f'Debe especificar al menos un rol para la funcion "{funcion}" o "--all" para agregarlo a todos los roles.',
                )
                return

            await self.eliminar_funcion(data, funcion, roles_a_eliminar, user_id, is_admin, event)

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

    async def eliminar_funcion(self, data, funcion, roles_a_eliminar, user_id, is_admin, event):
        "Función auxiliar que valida permiso y elimina el rol de la función"
        PERMISO_BORRAR_FUNCION = Permisos.BORRAR_FUNCION.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        for rol in roles_a_eliminar:

            permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
            permiso = permiso_global | permiso_rol

            if (permiso & PERMISO_BORRAR_FUNCION) or is_admin:
                if rol in data["funciones"][funcion]:
                    data["funciones"][funcion].remove(rol)  # Borral rol de la funcion
                    await self.save_data(data, event)
                    await Utils.response(
                        event,
                        f'Rol "{rol}" eliminado de la función "{funcion}".',
                    )
                else:
                    await Utils.response(
                        event,
                        f'La función "{funcion}" no está asignada al rol "{rol}".',
                    )
            else:
                mensajes.append(f"Permisos insuficientes para eliminar el rol {rol}.")
                # Muestra los permisos de quien ejecuta si no pudo eliminar
                nivel_actual = data["nivel"].get(rol, {}).get(user_id, 0)
                permisos_actuales = Permisos.permisos_usuario(nivel_actual)
                permisos_actuales_str = ", ".join(permisos_actuales)
                mensajes.append(f'Permisos del usuario "{user_id}" en el grupo "{rol}": {permisos_actuales_str}.')

        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    @match_regex(r"!agregar_usuario\s*(?P<help>--help|-h)?\s*(?P<usuario>\w+)?\s*(?P<rol>\w+)?\s*(?P<all>--all|-a)?")
    async def agregar_usuario(self, event):
        """
        Agrega un usuario al sistema si quien ejecuta el comando tiene el permiso correspondiente.
        """

        help_option = event.regex.group("help")
        all_option = event.regex.group("all")

        if help_option:
            help_message = (
                
                "Descripción: Agrega al usuario especificado a uno o más roles.\n"
                "Uso: !agregar_usuario <usuario> [rol] [--help|-h] [--all|-a]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "            --all, -a     Agrega al usuario a todos los roles.\n"
                "Ejemplo:\n"
                "            !agregar_usuario jgarberi DEIRET\n"
                "            !agregar_usuario jgarberi --all\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            usuario = event.regex.group("usuario")
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(usuario):
                raise ValueError('El usuario "{usuario}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper() if rol else None  # Convertir a mayúsculas si es válido

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)
            is_usuario = Utils.is_member(data, usuario)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Obtener roles del usuario que ejecuta el comando
            roles_user_id = data["miembros"].get(user_id, [])

            # Determina qué roles agregar
            roles_a_agregar = []

            if all_option:
                roles_a_agregar = roles_user_id  # Agregar todos los roles
            elif rol:
                if rol not in data["roles"]:
                    raise ValueError(f'El rol "{rol}" no existe.')

                roles_a_agregar.append(rol)

            Utils.log_info(f"roles a agregar: {roles_a_agregar}")

            # Verificación adicional para administradores
            if not roles_a_agregar and is_admin:  # si no se paso rol y sos admin, agrega al usuario sin asignar rol
                if not is_usuario:
                    data["miembros"][usuario] = []
                    await self.save_data(data, event)
                    await Utils.response(event, f'Usuario "{usuario}" añadido al sistema.')
                    return
                else:
                    await Utils.response(event, f'Usuario "{usuario}" existente en el sistema.')
                    return

            if not roles_a_agregar and not is_admin:
                await Utils.response(
                    event,
                    f'Debe especificar al menos un rol para el usuario "{usuario}" o "--all" para agregarlo a todos los roles.',
                )
                return

            await self.agregar_roles(data, usuario, roles_a_agregar, user_id, is_admin, event)

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

    async def agregar_roles(self, data, usuario, roles_a_agregar, user_id, is_admin, event):
        PERMISO_AGREGAR_USUARIO = Permisos.AGREGAR_USUARIO.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        for rol in roles_a_agregar:
            permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
            permiso = permiso_global | permiso_rol

            if (permiso & PERMISO_AGREGAR_USUARIO) or is_admin:
                await self.agregar_usuario_a(data, usuario, "miembros", event, mensajes, rol)
            else:
                # await Utils.response(event, f'Permisos insuficientes para agregar al usuario "{usuario}".')
                mensajes.append(f'Permisos insuficientes para agregar al usuario "{usuario}".')
        # Envía todos los mensajes acumulados de una sola vez
        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    async def agregar_usuario_a(
        self,
        data,
        usuario,
        categoria,
        event,
        mensajes,
        rol=None,
    ):
        """Función auxiliar que agrega un rol a un usuario"""
        if categoria == "miembros":
            if usuario not in data[categoria]:
                data[categoria][usuario] = []
                await self.save_data(data, event)
                Utils.log_info(
                    f'Usuario "{usuario}" añadido.\nEstado actual de la categoría {categoria}: {data[categoria]}\n'
                )
                # await Utils.response(event, f'Usuario "{usuario}" añadido al sistema.')
                mensajes.append(f'Usuario "{usuario}" añadido al sistema.')

            if rol not in data[categoria][usuario]:
                Utils.log_info(f'Asignando el rol "{rol}" al usuario "{usuario}".')
                data[categoria][usuario].append(rol)
                await self.save_data(data, event)
                Utils.log_info(
                    f'Rol "{rol}" añadido al usuario "{usuario}".\nEstado actual de {categoria}: {data[categoria]}\n'
                )
                # await Utils.response(event, f'Usuario "{usuario}" añadido al rol "{rol}".')
                mensajes.append(f'Usuario "{usuario}" añadido al rol "{rol}".')

            else:
                # await Utils.response(event, f'El usuario "{usuario}" ya pertenece al rol "{rol}".')
                Utils.log_info(f'El usuario "{usuario}" ya pertenece al rol "{rol}".')
                mensajes.append(f'El usuario "{usuario}" ya pertenece al rol "{rol}".')

        Utils.log_info(f"Estado completo de la estructura de datos al finalizar: {data}")

    @match_regex(r"!borrar_usuario\s*(?P<help>--help|-h)?\s*(?P<usuario>\w+)?\s*(?P<rol>\w+)?\s*(?P<all>--all|-a)?")
    async def borrar_usuario(self, event):
        """
        Borra un usuario del sistema o de roles específicos si quien ejecuta el comando tiene el permiso correspondiente.
        """
        help_option = event.regex.group("help")
        all_option = event.regex.group("all")

        if help_option:
            help_message = (
                
                
                "Descripción: Elimina al usuario especificado de uno o más roles.\n"
                "Uso: !borrar_usuario <nombre_usuario> [rol] [--help|-h] [--all|-a]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "            --all, -a     Elimina al usuario de todos los roles.\n"
                "Ejemplo:\n"
                "            !borrar_usuario jgarberi DEIRET\n"
                "            !borrar_usuario jgarberi --all\n"
                "            !borrar_usuario jgarberi"
                
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            usuario = event.regex.group("usuario")
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(usuario):
                raise ValueError('El usuario "{usuario}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper() if rol else None  # Convertir a mayúsculas si es válido

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Obtener roles del usuario que ejecuta el comando
            roles_user_id = data["miembros"].get(user_id, [])

            # Determina qué roles eliminar
            roles_a_eliminar = []

            if all_option:
                roles_a_eliminar = roles_user_id  # Eliminar los roles segun quien ejecuta
            elif rol:
                if rol not in data["roles"]:
                    raise ValueError(f'El rol "{rol}" no existe.')

                roles_a_eliminar.append(rol)

            Utils.log_info(f"roles a eliminar: {roles_a_eliminar}")

            # Verificación adicional para administradores
            if not roles_a_eliminar and is_admin:  # si no se paso rol y sos admin, borra todo
                if usuario in data["miembros"]:
                    roles_a_eliminar = data["miembros"].get(usuario, []).copy()  # Importante
                    await self.eliminar_usuario(data, usuario, roles_a_eliminar, user_id, is_admin, event)
                    await Utils.response(event, f'Usuario "{usuario}" eliminado del sistema.')
                    return
                else:
                    await Utils.response(event, f'Usuario "{usuario}" no existe en el sistema.')
                    return

            if not roles_a_eliminar and not is_admin:
                await Utils.response(
                    event,
                    f'Debe especificar al menos un rol para el usuario "{usuario}" \n \
                    "--all" para eliminarlo de todos los roles \n \
                    "--help", para mas información.',
                )
                return

            await self.eliminar_usuario(data, usuario, roles_a_eliminar, user_id, is_admin, event)

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

    # Función auxiliar
    async def eliminar_usuario(self, data, usuario, roles_a_eliminar, user_id, is_admin, event):
        """Función auxiliar que elimina el rol de un usuario"""
        PERMISO_BORRAR_USUARIO = Permisos.BORRAR_USUARIO.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        for rol in roles_a_eliminar:

            permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
            permiso = permiso_global | permiso_rol

            if (permiso & PERMISO_BORRAR_USUARIO) or is_admin:
                await self.eliminar_usuario_de(data, usuario, "miembros", rol, event, mensajes)
                await self.eliminar_usuario_de(data, usuario, "creadores", rol, event, mensajes)
                await self.eliminar_usuario_de(data, usuario, "nivel", rol, event, mensajes)
                await self.eliminar_usuario_de(
                    data, usuario, "nivel", "__global__", event, mensajes
                )  # __global__ no es un rol
                await self.eliminar_usuario_de(data, usuario, "telegram", rol, event, mensajes)
                await self.save_data(data, event)
            else:
                # await Utils.response(event, f'Permisos insuficientes para eliminar al usuario "{usuario}" del rol {rol}.')
                mensajes.append(f'Permisos insuficientes para eliminar al usuario "{usuario}" del rol {rol}.')
                # Muestra los permisos de quien ejecuta si no pudo eliminar
                nivel_actual = data["nivel"].get(rol, {}).get(user_id, 0)
                permisos_actuales = Permisos.permisos_usuario(nivel_actual)
                permisos_actuales_str = ", ".join(permisos_actuales)
                # await Utils.response(event, f'Permisos del usuario "{user_id}" en el grupo "{rol}": {permisos_actuales_str}.')
                mensajes.append(f'Permisos del usuario "{user_id}" en el grupo "{rol}": {permisos_actuales_str}.')

        # Envía todos los mensajes acumulados de una sola vez
        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    async def eliminar_usuario_de(self, data, usuario, categoria, rol, event, mensajes):
        """Función auxiliar que elimina al usuario de todo los nivels"""

        # Logica para miembros
        if categoria == "miembros":
            if usuario in data["miembros"]:
                if rol in data["miembros"][usuario]:
                    data["miembros"][usuario].remove(rol)  # Eliminar rol de la lista de roles del usuario
                    # await Utils.response(event, f'Usuario "{usuario}" eliminado del rol "{rol}" en miembros.')
                    mensajes.append(f'Usuario "{usuario}" eliminado del rol "{rol}" en miembros.')

                    # Verifica si la lista de roles del usuario queda vacía y lo elimina
                    if not data["miembros"][usuario]:
                        del data["miembros"][usuario]
                        # await Utils.response(event, f'Usuario "{usuario}" eliminado de miembros porque no tiene roles.')
                        mensajes.append(f'Usuario "{usuario}" eliminado de miembros porque no tiene roles.')
                else:
                    # await Utils.response(event, f'El usuario "{usuario}" no pertenece al grupo "{rol}".')
                    mensajes.append(f'El usuario "{usuario}" no pertenece al grupo "{rol}".')
            else:
                # await Utils.response(event, f'El usuario "{usuario}" no está registrado en el sistema.')
                mensajes.append(f'El usuario "{usuario}" no está registrado en el sistema.')
            return

        # Lógica para __global__
        if categoria == "nivel" and rol == "__global__":
            roles_usuario = self.obtener_roles_usuario(data, usuario)
            if not roles_usuario:
                if usuario in data["nivel"].get("__global__", {}):
                    del data["nivel"]["__global__"][usuario]
                    # await Utils.response(event, f'Usuario "{usuario}" eliminado de __global__')
                    mensajes.append(f'Usuario "{usuario}" eliminado de __global__')
            return  # Evitar lógica adicional

        # Lógica para telegram
        if categoria == "telegram":
            if not data["miembros"].get(usuario, []):
                # Buscar el ID de Telegram del usuario a eliminar
                user_telegram_id = next(
                    (telegram_id for telegram_id, info in data["telegram"].items() if info.get("username") == usuario),
                    None,
                )
                # Si se encuentra el ID de Telegram, eliminar al usuario
                if user_telegram_id:
                    del data["telegram"][user_telegram_id]
                    # await Utils.response(event, f'Usuario "{usuario}" eliminado de Telegram.')
                    mensajes.append(f'Usuario "{usuario}" eliminado de Telegram.')
                else:
                    # await Utils.response(event, f'No se encontró un usuario "{usuario}" en Telegram.')
                    mensajes.append(f'No se encontró un usuario "{usuario}" en Telegram.')

            return  # Evitar ejecutar lógica adicional

        # Lógica para lista (ej "creadores")
        if isinstance(data.get(categoria, {}).get(rol), list):
            if usuario in data[categoria][rol]:
                data[categoria][rol].remove(usuario)
                # await Utils.response(event, f'Usuario "{usuario}" eliminado del rol "{rol}" en la categoría "{categoria}".')
                mensajes.append(f'Usuario "{usuario}" eliminado del rol "{rol}" en la categoría "{categoria}".')
                # Si el rol queda vacío, lo eliminamos
                if not data[categoria][rol]:
                    del data[categoria][rol]
                    # await Utils.response(event, f'Rol "{rol}" eliminado de la categoría "{categoria}" porque quedó vacío.')
                    mensajes.append(f'Rol "{rol}" eliminado de la categoría "{categoria}" porque quedó vacío.')
            return  # Evitar lógica adicional

        # Lógica para diccionarios (ej "nivel")
        elif isinstance(data.get(categoria, {}).get(rol), dict):
            if usuario in data[categoria][rol]:
                del data[categoria][rol][usuario]
                # await Utils.response(event, f'Usuario "{usuario}" eliminado de "{rol}" en la categoría "{categoria}".')
                mensajes.append(f'Usuario "{usuario}" eliminado de "{rol}" en la categoría "{categoria}".')
                # Si no quedan usuarios en este rol, lo eliminamos
                if not data[categoria][rol]:
                    del data[categoria][rol]
                    # await Utils.response(event, f'Rol "{rol}" eliminado de la categoría "{categoria}" porque quedó vacío.')
                    mensajes.append(f'Rol "{rol}" eliminado de la categoría "{categoria}" porque quedó vacío.')
            return  # Evitar lógica adicional

    @match_regex(r"!agregar_permiso\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?\s*(?P<usuario>\w+)?\s*(?P<permiso>\w+)?")
    async def agregar_permiso(self, event):
        """
        Agrega el nivel de permiso de un usuario en un rol específico.
        """

        help_option = event.regex.group("help")

        if help_option:
            help_message = (
                
                "Descripción: Agrega permisos en el usuario y rol especificado.\n"
                "Uso: !agregar_permiso <rol> <usuario> <funcion< [--help|-h]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !agregar_permiso DEIRET jgarberi AGREGAR_USUARIO\n"
                
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            usuario = event.regex.group("usuario")
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(usuario):
                raise ValueError('El usuario "{usuario}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper()  # Convertir a mayúsculas si es válido

            # Captura permiso
            permiso = event.regex.group("permiso")
            if not permiso:
                raise ValueError("Debe especificar rol, usuario y permiso o --help para más ayuda.")

            if not Utils.validar_cadena_permiso(permiso):
                raise ValueError(f'El permiso "{permiso}" posee caracteres inválidos.')

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)
            is_nivel = Utils.is_nivel(data, rol)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            if not is_nivel:
                raise ValueError(f'El rol "{rol}" no es válido\n. Permisos disponibles: {Utils.listar_roles(data)}')

            if permiso not in PERMISOS_MAPA:
                raise ValueError(
                    f'El permiso "{permiso}" no es válido\n. Permisos disponibles: {", ".join(PERMISOS_MAPA.keys())}'
                )

            await self.agregar_permiso_a(data, rol, usuario, permiso, user_id, is_admin, event)

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

    async def agregar_permiso_a(self, data, rol, usuario, permiso_nuevo, user_id, is_admin, event):
        """Función auxiliar para agregar permiso"""
        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)
        permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
        permiso = permiso_global | permiso_rol
        permiso_nuevo_valor = PERMISOS_MAPA[permiso_nuevo]

        if (permiso & PERMISO_ADMIN_GRUPO) or is_admin:

            permiso_actual = (
                data["nivel"].get(rol, {}).get(usuario, 0)
            )  # Obtener el nivel actual del usuario en el grupo
            permiso_actualizado = permiso_actual | permiso_nuevo_valor
            data["nivel"][rol][usuario] = int(permiso_actualizado)
            await self.save_data(data, event)
            mensajes.append(f'Nivel de {usuario} en el grupo "{rol}" ha sido actualizado a {permiso_actualizado}.')
            permisos_actuales = data["nivel"].get(rol, {}).get(usuario, 0)  # Mostrar los permisos actualizados integer
            permisos_actuales_str = ", ".join(Permisos.permisos_usuario(permisos_actuales))
            mensajes.append(f'Permisos actuales de usuario "{usuario}" en rol "{rol}": {permisos_actuales_str}.')
        else:
            await Utils.response(
                event,
                f'Permisos insuficientes para modificar el nivel de permisos en el grupo "{rol}".',
            )

        # Envía todos los mensajes acumulados de una sola vez
        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    @match_regex(r"!borrar_permiso\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?\s*(?P<usuario>\w+)?\s*(?P<permiso>\w+)?")
    async def borrar_permiso(self, event):
        """
        Borra el nivel de permiso de un usuario en un rol específico.        }
        """

        help_option = event.regex.group("help")

        if help_option:
            help_message = (
                "Descripción: Quita permisos en el usuario y rol especificado.\n"
                "Uso: !agregar_usuario <nombre_usuario> [rol] [--help|-h] [--all|-a]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !agregar_permiso jgarberi DEIRET AGREGAR_USUARIO\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

            # Verifica si los datos se han cargado correctamente
            if data is None:
                raise ValueError("No se pudo cargar la estructura de datos.")

            connector_type, continue_execution = await self.pre_process(event)
            if not continue_execution:  # usuario de telegram no autorizado
                raise ValueError(f"connector_type: {connector_type} continue_execution: {continue_execution}")

            if connector_type == "websocketmod":
                if not Utils.validar_cadena(user_id):
                    raise ValueError('El usuario "{user_id}" posee caracteres inválidos.')

            # con tg_id que viene por el conector, se obtiene el username
            elif connector_type == "telegrampost":
                tg_id = user_id
                user_id = self.get_username_by_id(data, tg_id)

            user_id = user_id.lower()

            usuario = event.regex.group("usuario")
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(usuario):
                raise ValueError('El usuario "{usuario}" posee caracteres inválidos.')

            # Captura rol
            rol = event.regex.group("rol") or None
            if rol and not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper()  # Convertir a mayúsculas si es válido

            # Captura permiso
            permiso = event.regex.group("permiso")
            if not permiso:
                raise ValueError("Debe especificar rol, usuario y permiso o --help para más ayuda.")

            if not Utils.validar_cadena_permiso(permiso):
                raise ValueError(f'El permiso "{permiso}" posee caracteres inválidos.')

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)
            is_nivel = Utils.is_nivel(data, rol)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            if not is_nivel:
                raise ValueError(f'El rol "{rol}" no es válido\n. Permisos disponibles: {Utils.listar_roles(data)}')

            if permiso not in PERMISOS_MAPA:
                raise ValueError(
                    f'El permiso "{permiso}" no es válido\n. Permisos disponibles: {", ".join(PERMISOS_MAPA.keys())}'
                )

            await self.borrar_permiso_a(data, rol, usuario, permiso, user_id, is_admin, event)

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

    async def borrar_permiso_a(self, data, rol, usuario, permiso_nuevo, user_id, is_admin, event):
        """Función auxiliar para borrar permiso"""
        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value
        permiso = 0
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)
        permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
        permiso = permiso_global | permiso_rol  # user_id
        permiso_nuevo_valor = PERMISOS_MAPA[permiso_nuevo]  #

        if (permiso & PERMISO_ADMIN_GRUPO) or is_admin:

            permiso_actual = (
                data["nivel"].get(rol, {}).get(usuario, 0)
            )  # Obtener el nivel actual del usuario en el grupo
            permiso_actualizado = permiso_actual & ~permiso_nuevo_valor
            data["nivel"][rol][usuario] = int(permiso_actualizado)
            await self.save_data(data, event)
            mensajes.append(f'Nivel de {usuario} en el grupo "{rol}" ha sido actualizado a {permiso_actualizado}.')
            permisos_actuales = data["nivel"].get(rol, {}).get(usuario, 0)  # Mostrar los permisos actualizados integer
            permisos_actuales_str = ", ".join(Permisos.permisos_usuario(permisos_actuales))
            mensajes.append(f'Permisos actuales de usuario "{usuario}" en rol "{rol}": {permisos_actuales_str}.')
        else:
            await Utils.response(
                event,
                f'Permisos insuficientes para modificar el nivel de permisos en el grupo "{rol}".',
            )

        # Envía todos los mensajes acumulados de una sola vez
        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    @match_regex(r"!agregar_rol\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?")
    async def agregar_rol(self, event):
        """
        Agrega un rol al sistema.
        """
        help_option = event.regex.group("help")
        if help_option:
            help_message = (
                "Descripción: Agrega un rol al sistema.\n"
                "Uso: !agregar_rol <rol> [--help|-h]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !agregar_rol DEIRET\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            rol = event.regex.group("rol")  # Captura
            if not rol:
                raise ValueError("Debe especificar el rol o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper()

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Verifica si el rol  existe
            if rol in data["roles"]:
                raise ValueError(f'El rol "{rol}" ya existe.')

            PERMISO_AGREGAR_GRUPO = Permisos.AGREGAR_GRUPO.value
            permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

            # Verificar el permiso global del usuario que no es admin, para agregar el rol
            if (permiso_global & PERMISO_AGREGAR_GRUPO) or is_admin:

                data["roles"].append(rol)  # Agregar el rol
                await self.save_data(data, event)
                await Utils.response(event, f'Rol "{rol}" añadido correctamente.')
                return

            # Si no tiene permisos, envía un mensaje de error
            await Utils.response(event, "Permisos insuficientes para agregar un rol.")

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

    @match_regex(r"!borrar_rol\s*(?P<help>--help|-h)?\s*(?P<value>\w+)?")
    async def borrar_rol(self, event):
        """
        Elimina un rol del sistema.
        """

        help_option = event.regex.group("help")

        if help_option:
            help_message = (
                "Descripción: Agrega un rol al sistema.\n"
                "Uso: !borrar_rol <rol> [--help|-h]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !borrar_rol DEIRET\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            rol = event.regex.group("value")  # Captura

            if not rol:
                raise ValueError(event, "Debe especificar el rol o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper()

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Verifica si el rol no existe
            if rol not in data["roles"]:
                raise ValueError(f'El rol "{rol}" no existe.')

            await self.eliminar_rol(data, rol, user_id, is_admin, event)

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

    # Función auxiliar

    async def eliminar_rol(self, data, rol, user_id, is_admin, event):
        """Función auxiliar para eliminar rol"""
        PERMISO_BORRAR_GRUPO = Permisos.BORRAR_GRUPO.value
        mensajes = []
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        # Verifica el permiso global del usuario que no es admin, para borrar el rol
        if (permiso_global & PERMISO_BORRAR_GRUPO) or is_admin:
            await self.eliminar_rol_de(data, "roles", rol, event, mensajes)
            await self.eliminar_rol_de(data, "creadores", rol, event, mensajes)
            await self.eliminar_rol_de(data, "funciones", rol, event, mensajes)
            await self.eliminar_rol_de(data, "miembros", rol, event, mensajes)
            await self.eliminar_rol_de(data, "ayuda", rol, event, mensajes)
            await self.eliminar_rol_de(data, "nivel", rol, event, mensajes)
            await self.save_data(data, event)
        else:
            mensajes.append(f"Permisos insuficientes para eliminar el rol {rol}.")
            # Muestra los permisos de quien ejecuta si no pudo eliminar
            nivel_actual = data["nivel"].get(rol, {}).get(user_id, 0)
            permisos_actuales = Permisos.permisos_usuario(nivel_actual)
            permisos_actuales_str = ", ".join(permisos_actuales)
            mensajes.append(f'Permisos del usuario "{user_id}" en el grupo "{rol}": {permisos_actuales_str}.')

        if mensajes:
            await Utils.response(event, "\n".join(mensajes))

    async def eliminar_rol_de(self, data, categoria, rol, event, mensajes):
        if categoria == "roles":
            data[categoria].remove(rol)
            mensajes.append(f'Rol "{rol}" eliminado correctamente de "{categoria}".')

        if categoria == "creadores":
            if rol in data.get(categoria, {}):  # Borrar el rol de los creadores
                del data[categoria][rol]
                mensajes.append(f'Rol "{rol}" eliminado correctamente de "{categoria}".')

        if categoria == "funciones":
            for funcion, roles in data.get(categoria, {}).items():  # Borrar el rol de las funciones
                if rol in roles:
                    roles.remove(rol)
                    mensajes.append(
                        f'Rol "{rol}" eliminado correctamente de la función "{funcion}" de la categoria "{categoria}".'
                    )

        if categoria == "miembros":
            for miembro, roles in data.get(categoria, {}).items():  # Borrar el rol de los miembros
                if rol in roles:
                    roles.remove(rol)
                    mensajes.append(
                        f'Rol "{rol}" eliminado correctamente del usuario "{miembro}" de la categoria "{categoria}".'
                    )

        if categoria == "ayuda":
            if rol in data.get(categoria, {}):  # Borrar el rol de la ayuda
                del data[categoria][rol]
                mensajes.append(f'Rol "{rol}" eliminado correctamente de "{categoria}".')

        if categoria == "nivel":
            if rol in data.get(categoria, {}):  # Borrar los niveles asociados al grupo
                del data[categoria][rol]
                mensajes.append(f'Rol "{rol}" eliminado correctamente de "{categoria}".')

    @match_regex(r"!asociar_telegram_usuario\s*(?P<help>--help|-h)?\s*(?P<tg_id>\w+)\s+(?P<usuario>\w+)")
    async def asociar_telegram_usuario(self, event):
        """
        Asocia un ID de Telegram a un usuario del sistema.
        """

        help_option = event.regex.group("help")

        if help_option:
            help_message = (
                "Descripción: Asocia un ID de Telegram a un usuario.\n"
                "Uso: !asociar_telegram_usuario <telegram_id> <usuario> [--help|-h]\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !asociar_telegram_usuario 0123456789 jgarberi\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            usuario = event.regex.group("usuario")
            # Valida cadena
            if not usuario:
                raise ValueError("Debe especificar el nombre de usuario o --help para más ayuda.")

            tg_id = event.regex.group("tg_id")
            # Valida cadena
            if not Utils.validar_tg_id(tg_id):
                await Utils.response(event, f'El id de Telegram "{tg_id}" es inválido.')
                return

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            await self.agregar_telegram_a(data, usuario, tg_id, user_id, is_admin, event)

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

    async def agregar_telegram_a(self, data, usuario, tg_id, user_id, is_admin, event):
        """Función auxiliar para asociar username a tg_id"""
        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value

        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)

        # Verifica si el username ya está asociado a otro telegram_user_id y lo elimina
        for _tg_id, user_info in data["telegram"].items():
            if user_info.get("username") == usuario and _tg_id != tg_id:
                del data["telegram"][_tg_id]
                break

        # Verifica si el tg_id ya está asociado a otro usuario
        if tg_id in data["telegram"]:
            await Utils.response(
                event,
                f'El ID de Telegram "{tg_id}" \
                      ya está asociado con el usuario "{data["telegram"][tg_id]["username"]}".',
            )
            return

        # Verificar el permiso global del usuario que no es admin, para agregar el rol
        if (permiso_global & PERMISO_ADMIN_GRUPO) or is_admin:
            # Si el usuario tiene permisos, asociar el nuevo username
            data["telegram"][str(tg_id)] = {"username": usuario}
            await self.save_data(data, event)
            await Utils.response(event, f'Telegram id "{tg_id}" asociado a {usuario} correctamente.')
            return

        # Si no tiene permisos, envía un mensaje de error
        await Utils.response(event, "Permisos insuficientes para agregar un grupo.")

    @match_regex(r"!agregar_ayuda\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?\s*(?P<mensaje_ayuda>.+)?")
    async def agregar_ayuda(self, event):
        """
        Agrega la ayuda a un rol.
        """
        help_option = event.regex.group("help")
        if help_option:
            help_message = (
                "Descripción: Agrega ayuda a un rol al sistema.\n"
                "Uso: !agregar_ayuda <rol> <mensaje>\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                '            !agregar_ayuda DEIRET "Esto en un mensaje de ayuda" DEIRET\n'
            )
            await Utils.response(event, help_message)
            return
        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            rol = event.regex.group("rol")  # Captura
            if not rol:
                raise ValueError("Debe especificar el rol o --help para más ayuda.")

            # Valida cadena
            if not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" posee caracteres inválidos.')

            rol = rol.upper()

            mensaje_ayuda = event.regex.group("mensaje_ayuda")  # Captura
            if not mensaje_ayuda:
                raise ValueError("Debe especificar el mensaje de ayuda o --help para más ayuda.")

            is_member = Utils.is_member(data, user_id)
            is_admin = Utils.is_admin(data, user_id)

            # Verifica que el user_id exista o sea admin
            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Verifica si el rol  existe
            if rol not in data["roles"]:
                raise ValueError(f'El rol "{rol}" no existe en el sistema.')

            await self.agregar_ayuda_a(data, rol, mensaje_ayuda, user_id, is_admin, event)

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

    async def agregar_ayuda_a(self, data, rol, mensaje_ayuda, user_id, is_admin, event):
        "Función auxiliar para agregfar ayuda"
        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value
        permiso = 0
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)
        permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
        permiso = permiso_global | permiso_rol

        if (permiso & PERMISO_ADMIN_GRUPO) or is_admin:
            data["ayuda"][rol] = mensaje_ayuda  # Actualizar la ayuda en el JSON
            await self.save_data(data, event)
            await Utils.response(event, f"Se actualizó la ayuda para {rol} a: {mensaje_ayuda}")
        else:
            Utils.response(
                event,
                f'Permisos insuficientes para modificar la ayuda en el rol "{rol}".',
            )

    @match_regex(r"!borrar_ayuda\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?")
    async def borrar_ayuda(self, event):
        """
        Borra la ayuda para un rol específico.
        """
        help_option = event.regex.group("help")
        if help_option:
            help_message = (
                "Descripción: Borra la ayuda asociada a un rol en el sistema.\n"
                "Uso: !borrar_ayuda <rol>\n"
                "Opciones:\n"
                "            --help, -h    Muestra este mensaje de ayuda.\n"
                "Ejemplo:\n"
                "            !borrar_ayuda DEIRET\n"
            )
            await Utils.response(event, help_message)
            return

        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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

            # Captura el rol de la entrada del usuario
            rol = event.regex.group("rol")
            if not rol:
                raise ValueError("Debe especificar el rol o --help para más ayuda.")

            # Valida el rol
            if not Utils.validar_cadena(rol):
                raise ValueError(f'El rol "{rol}" contiene caracteres inválidos.')

            rol = rol.upper()

            # Verifica que el rol exista en los datos y tenga ayuda asignada
            if rol not in data.get("roles", []):
                raise ValueError(f'El rol "{rol}" no existe en el sistema.')

            # Verifica si el usuario tiene permiso para borrar la ayuda
            is_admin = Utils.is_admin(data, user_id)
            is_member = Utils.is_member(data, user_id)

            if not is_member and not is_admin:
                raise ValueError(f'El usuario "{user_id}" no existe en el sistema')

            # Llamada a la función de borrado de ayuda
            await self.borrar_ayuda_de(data, rol, user_id, is_admin, event)

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

    async def borrar_ayuda_de(self, data, rol, user_id, is_admin, event):
        """Función auxiliar para borrar ayuda"""
        PERMISO_ADMIN_GRUPO = Permisos.ADMIN_GRUPO.value
        permiso = 0
        permiso_global = data["nivel"].get("__global__", {}).get(user_id, 0)
        permiso_rol = data["nivel"].get(rol, {}).get(user_id, 0)
        permiso = permiso_global | permiso_rol

        # Verifica permisos para borrar
        if (permiso & PERMISO_ADMIN_GRUPO) or is_admin:
            if rol in data["ayuda"]:
                del data["ayuda"][rol]  # Borra la ayuda del JSON
                await self.save_data(data, event)
                await Utils.response(event, f"La ayuda para el rol '{rol}' ha sido borrada.")
            else:
                await Utils.response(event, f"No existe ayuda definida para el rol '{rol}'.")
        else:
            await Utils.response(
                event,
                f"Permisos insuficientes para borrar la ayuda en el grupo '{rol}'.",
            )

    @match_regex(r"!mostrar_ayuda\s*(?P<help>--help|-h)?\s*(?P<rol>\w+)?")
    async def mostrar_ayuda(self, event):
        """
        Muestra la ayuda para un rol específico o todos los roles si no se especifica uno.
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
        try:
            user_id = Utils.get_userid(event)

            # Carga la estructura de datos que contiene los grupos
            data = await self.load_data(event)

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
                # Muestra la ayuda de todos los roles
                todas_ayudas = [f"{rol}: {mensaje}" for rol, mensaje in data.get("ayuda", {}).items()]
                if todas_ayudas:
                    await Utils.response(
                        event,
                        "Ayuda para todos los roles:\n" + "\n".join(todas_ayudas),
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
    

