from opsdroid.skill import Skill # type: ignore
from opsdroid.matchers import match_regex # type: ignore
from voluptuous import Required # type: ignore
from opsdroid.events import Message # type: ignore
#import redis
import logging

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    Required("host"): str,
    Required("port"): str,
    Required("db"): str,
    Required("password"): str
}

class MemorySkill(Skill):
    def __init__(self, opsdroid, config):
       super(MemorySkill, self).__init__(opsdroid, config)
       import sys
       #self.redis_host = config.get('host')  # Redis host from config
       #self.redis_port = config.get('port')  # Redis port from config
       #self.redis_db = int(config.get('db'))
       #self.redis_pass = config.get('password')
       #self.client = redis.Redis(host=self.redis_host, port=self.redis_port, db= self.redis_db, password=self.redis_pass)
       self.list_set_key = "list_names"  # Clave para almacenar los nombres de las listas
       sys.path.append("/modules")
     

    @match_regex(r'^!memory_set (.+) (.+)$')
    async def set_value(self, event):
        from utils import Utils
        """Almacenar un valor usando memory (Opsdroid memory como backend)."""
        key, value = event.regex.group(1), event.regex.group(2)
        await self.opsdroid.memory.put(key, value)  # Guardar el valor en Redis
        
        if Utils.is_websocket(event):
            await event.respond(Utils.encode_base64(f'Valor almacenado para {key}: {value}'))
        else:
            await event.respond(f'Valor almacenado para {key}: {value}')


    @match_regex(r'^!memory_get (.+)$')
    async def get_value(self, event):
        from utils import Utils
        """Obtener un valor desde memory (Opsdroid memory como backend)."""
        key = event.regex.group(1)
        value = await self.opsdroid.memory.get(key)  # Obtener el valor desde Redis
        
        if value:
            response = f'El valor para {key} es: {value}'
        else:
            response = f'No se encontró valor para {key}'

        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)

    
    #@match_regex(r'^!create_list (.+)$')
    @match_regex(r'^!create_list(?: help)?(?: (.+))?$')
    async def create_list(self, event):
        """Crear una lista en memory"""
        from utils import Utils
        list_name = event.regex.group(1)
        
        if event.regex.group(1) is None:
            help_message = (
            "Uso del comando `!create_list`:\n\n"
            "`!create_list <nombre_lista>`: Crea una lista con el nombre proporcionado.\n"
            "Si el nombre de la lista ya existe, se notificará que la lista ya está creada."
            )
            if Utils.is_websocket(event):
                encoded_help_message = Utils.encode_base64(help_message)
                await event.respond(encoded_help_message)
            else:
                await event.respond(help_message)
            return
        
        current_list_names = await self.opsdroid.memory.get(self.list_set_key, [])  # recupera listas existentes
        
        if list_name not in current_list_names: # si la lista no existe, la crea
            current_list_names.append(list_name)
            await self.opsdroid.memory.put(self.list_set_key, current_list_names) # agrega el nombre de la lista a la lista de nombres de listas
            await self.opsdroid.memory.put(list_name, []) # creauna lista vacia
            response = f'Lista "{list_name}" creada.'
        else:
            response = f'La lista "{list_name}" ya existe.'

        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)

    @match_regex(r'^!add_to_list (.+) (.+)$')
    async def add_to_list(self, event):
        from utils import Utils
        """Agregar un elemento a una lista en memory."""
        list_name, item = event.regex.group(1), event.regex.group(2)
        current_list = await self.opsdroid.memory.get(list_name)
        
        if current_list is None:
            current_list = ""
            
        # Agregar el nuevo item a la lista
        if current_list:
            current_list += "," + item
        else:
            current_list = item

        await self.opsdroid.memory.put(list_name, current_list)
        response = f'Elemento "{item}" agregado a la lista "{list_name}".'

        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)


    @match_regex(r'^!get_list (.+)$')
    async def get_list(self, event):
        from utils import Utils
        """Obtener todos los elementos de una lista en memory."""
        list_name = event.regex.group(1)
        items = await self.opsdroid.memory.get(list_name)
        
        if items:
            items = items.split(",")  # Separar los elementos por comas
            response = f'Elementos en la lista "{list_name}": {", ".join(items)}'
        else:
            response = f'La lista "{list_name}" está vacía o no existe.'

        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)


    @match_regex(r'^!list_all$')
    async def list_all_lists(self, event):
        from utils import Utils
        """Obtener todas las listas disponibles"""
        list_names = await self.opsdroid.memory.get(self.list_set_key, [])
        if list_names:
            response = "Listas disponibles: " + ", ".join(list_names)
        else:
            response = "No hay listas disponibles."

        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)


    @match_regex(r'^!remove_from_list (.+) (.+)$')
    async def remove_user_from_list(self, event):
        from utils import Utils
        """Eliminar un usuario de una lista usando memory (Opsdroid memory como backend)."""
        list_name, user = event.regex.group(1), event.regex.group(2)
        
        # Obtener la lista desde Opsdroid memory

        list_key = list_name
        list_data = await self.opsdroid.memory.get(list_key)

        
        if list_data:
            
            if isinstance(list_data, str):
                list_data = list_data.split(',')  # Convertir cadena separada por comas a lista
            
            # Eliminar el usuario de la lista si existe
            if user in list_data:
                list_data.remove(user)
                await self.opsdroid.memory.put(list_key, list_data)  # Actualizar la lista en la memoria
                
                response = f'Usuario {user} eliminado de la lista {list_name}.'
            else:
                response = f'Usuario {user} no encontrado en la lista {list_name}.'
        else:
            response = f'La lista {list_name} no existe.'

        # Manejo de respuesta según si es websocket o no
        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)

    
    @match_regex(r'^!delete_list (.+)$')
    async def delete_list(self, event):
        from utils import Utils
        """Eliminar una lista completa usando memory (Opsdroid memory como backend)."""
        list_name = event.regex.group(1)
        
        # Generar la clave de la lista
        list_key = list_name
        
        # Verificar si la lista existe
        list_data = await self.opsdroid.memory.get(list_key)
        if isinstance(list_data, str):
                list_data = list_data.split(',') 

        if not list_data:
            response = f'La lista {list_name} no existe.'
            if Utils.is_websocket(event):
                await event.respond(Utils.encode_base64(response))
            else:
                await event.respond(response)
            return

        # Verificar si la lista está vacía
        if isinstance(list_data, list) and not list_data:
            response = f'La lista {list_name} está vacía. ¿Deseas eliminarla de todas formas? Responde con "!confirm_delete {list_name}".'
        else:
            response = f'La lista {list_name} contiene elementos. ¿Estás seguro de que deseas eliminarla? Responde con "!confirm_delete {list_name}".'

        # Almacenar solicitud de confirmación
        self.deletion_confirmation[list_name] = event.user

        # Enviar respuesta
        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)

    @match_regex(r'^!confirm_delete (.+)$') # casi bien no se elimina posiblemente name_list y delete(key)
    async def confirm_delete_list(self, event):
        from utils import Utils
        """Confirmar la eliminación de una lista."""
        list_name = event.regex.group(1)

        # Verificar si hay una solicitud de confirmación pendiente
        if list_name not in self.deletion_confirmation or self.deletion_confirmation[list_name] != event.user:
            response = f'No hay una solicitud de eliminación pendiente para la lista {list_name}.'
            if Utils.is_websocket(event):
                await event.respond(Utils.encode_base64(response))
            else:
                await event.respond(response)
            return

        # Proceder a eliminar la lista
        list_key = list_name
        await self.opsdroid.memory.put(list_key, None)  # Eliminar la lista

        # Eliminar solicitud de confirmación
        del self.deletion_confirmation[list_name]

        response = f'La lista {list_name} ha sido eliminada con éxito.'
        if Utils.is_websocket(event):
            encoded_response = Utils.encode_base64(response)
            await event.respond(encoded_response)
        else:
            await event.respond(response)
    
    
    @match_regex(r'^!memory_help$')
    async def help(self, event):
        """Proporcionar una lista de comandos y su descripción"""
        from utils import Utils

        help_message = """
        Comandos disponibles:
        - `!create_list <nombre>`: Crear una lista con el nombre especificado.
        - `!add_to_list <lista> <elemento>`: Agregar un elemento a la lista especificada.
        - `!get_list <lista>`: Obtener los elementos de la lista especificada.
        - `!remove_from_list <lista> <elemento>`: Eliminar un elemento de la lista especificada.
        - `!delete_list <nombre>`: Eliminar la lista especificada.
        - `!list_all`: Listar todas las listas disponibles.
        """

        # Enviar respuesta según si el evento es por WebSocket o no
        if Utils.is_websocket(event):
            encoded_message = Utils.encode_base64(help_message)
            await event.respond(encoded_message)
        else:
            await event.respond(help_message)