from enum import Flag
import logging
_LOGGER = logging.getLogger(__name__)
class Permisos(Flag):

    AGREGAR_FUNCION = 1 #PUEDE AGREGAR NUEVA FUNCION A GRUPO AL CUAL PERTENECE
    BORRAR_FUNCION = 2  #PUEDE BORRAR FUNCION DE GRUPO AL CUAL PERTENECE
    AGREGAR_USUARIO = 4 #PUEDE AGREGAR NUEVO USUARIO A GRUPO AL CUAL PERTENECE
    BORRAR_USUARIO = 8  #PUEDE BORRAR USUARIO DE GRUPO AL CUAL PERTENECE
    ADMIN_GRUPO = 16    #PUEDE MODIFICAR PERMISOS A OTRO USUARIO DE GRUPO AL CUAL PERTENECE
    AGREGAR_GRUPO = 32  #PUEDE CREAR NUEVOS GRUPOS.
    BORRAR_GRUPO = 64   #PUEDE BORRAR GRUPOS QUE HAYA CREADO.
    ADMIN_GLOBAL = 128  #TIENE TODOS LOS PERMISOS. NO SE LE PUEDE SACAR POR OTRO USUARIO.

    
    def permiso_para_comando(command, userid, grupos):
        """Devuelve True si puede ejecutar el comando"""
        grupos_habilitados = set(grupos["funciones"][command])
        if userid in grupos["miembros"]:
            grupos_usuario = set(grupos["miembros"][userid])
            if len(grupos_usuario.intersection(grupos_habilitados)) > 0:
                return True
        return False
    
    
    def acl(command, userid, grupos):
        """
        Verifica si un usuario está autorizado para ejecutar un comando según los grupos a los que pertenece.

        Args:
            command (str): El comando que se desea ejecutar.
            userid (str): El identificador del usuario.
            grupos (dict): Un diccionario que contiene las funciones y los miembros. 
                Debe tener la estructura:
                {
                    "funciones": {
                        "comando1": ["grupo1", "grupo2"],
                        "comando2": ["grupo3"]
                    },
                    "miembros": {
                        "usuario1": ["grupo1", "grupo3"],
                        "usuario2": ["grupo2"]
                    }
                }

        Returns:
            tuple:
                - bool: `True` si el usuario está autorizado para ejecutar el comando, `False` en caso contrario.
                - str: Un mensaje informativo indicando si el usuario está autorizado o no.

        Example:
            >>> grupos = {
            ...     "funciones": {
            ...         "comando1": ["grupo1", "grupo2"],
            ...         "comando2": ["grupo3"]
            ...     },
            ...     "miembros": {
            ...         "usuario1": ["grupo1", "grupo3"],
            ...         "usuario2": ["grupo2"]
            ...     }
            ... }
            >>> acl("comando1", "usuario1", grupos)
            (True, 'usuario1 está habilitado para ejecutar comando1')
            >>> acl("comando2", "usuario2", grupos)
            (False, 'usuario2 no está habilitado para ejecutar comando2')
            >>> acl("comando3", "usuario3", grupos)
            (False, 'usuario3 no está habilitado para ejecutar comando3. No existe en la base.')
        """
    
        grupos_habilitados = set(grupos.get("funciones", {}).get(command, []))
        
        if userid in grupos.get("miembros", {}):
            grupos_usuario = set(grupos["miembros"].get(userid, []))
            
            if grupos_usuario & grupos_habilitados:
                return True, f"{userid} está habilitado para ejecutar {command}"
            return False, f"{userid} no está habilitado para ejecutar {command}"
        
        return False, f"{userid} no está habilitado para ejecutar {command}. No existe en la base."


    # def permisos(userid, grupos):
    #     if userid in grupos["miembros"]:
    #         grupos_usuario = set(grupos["miembros"][userid])
    #         for grupo in grupos_usuario:
    #             if userid in grupos["nivel"][grupo]:
    #                 nivel = grupos["nivel"][grupo][userid]
    #                 bitshift = 1 # Comienza con el bitshift de 1 y recorre los bits
    #                 while bitshift <= Permisos.ADMIN_GLOBAL.value:
    #                     permiso_bitshift = Permisos(bitshift)
                        
    #                     if nivel & bitshift: # Verifica si el bit correspondiente al permiso está activado
    #                         return True, f"Usuario {userid} en grupo {grupo} tiene {permiso_bitshift.name}"
                        
    #                     bitshift <<= 1 # Mueve al siguiente bit
    #     else:
    #         return False, f"{userid} no tiene permisos especiales."
    
    
    def permisos(userid, grupos):
        permisos = {}
        
        # Verificar permisos globales
        nivel_global = grupos["nivel"].get("__global__", {}).get(userid, 0)
        if nivel_global > 0:
            permisos["__global__"] = nivel_global  # Agregar permisos globales si existen
        # Verificar permisos de grupos específicos
        if userid in grupos["miembros"]:
            grupos_usuario = set(grupos["miembros"][userid])
            for grupo in grupos_usuario:
                if userid in grupos["nivel"].get(grupo, {}):
                    nivel = grupos["nivel"][grupo][userid]
                    permisos[grupo] = nivel  # Guardar el nivel binario en lugar de permisos como nombres
        return permisos

    def nivel_global(userid, grupos):
        nivel_global = grupos["nivel"].get("__global__", {}).get(userid, 0)
        return nivel_global


    def permisos_usuario(nivel):
        """
        Obtiene los permisos actuales de un usuario en función del nivel de permisos.
        Args:
            nivel: El nivel actual de permisos del usuario.
        
        Returns:
            Una lista de nombres de permisos que tiene el usuario.
        """
        PERMISOS_MAPA = {
            Permisos.AGREGAR_FUNCION.value: 'AGREGAR_FUNCION',
            Permisos.BORRAR_FUNCION.value: 'BORRAR_FUNCION',
            Permisos.AGREGAR_USUARIO.value: 'AGREGAR_USUARIO',
            Permisos.BORRAR_USUARIO.value: 'BORRAR_USUARIO',
            Permisos.ADMIN_GRUPO.value: 'ADMIN_GRUPO',
            Permisos.AGREGAR_GRUPO.value: 'AGREGAR_GRUPO',
            Permisos.BORRAR_GRUPO.value: 'BORRAR_GRUPO',
            Permisos.ADMIN_GLOBAL.value: 'ADMIN_GLOBAL'
        }
        permisos_actuales = [nombre_permiso for valor_permiso, nombre_permiso in PERMISOS_MAPA.items() if nivel & valor_permiso]
        return permisos_actuales

    
    def comandos_disponibles(userid, grupos):
            """Devuelve una lista de todos los comandos disponibles para un userid"""
            if userid in grupos["miembros"]:
                grupos_usuario = set(grupos["miembros"][userid])
                comandos_habilitados = []

                for comando, grupos_habilitados in grupos["funciones"].items(): # Recorremos todos los comandos en el diccionario "funciones"
                    grupos_habilitados = set(grupos_habilitados)   # Convertimos los grupos habilitados en un conjunto

                    if len(grupos_usuario.intersection(grupos_habilitados)) > 0: # Si el usuario pertenece a alguno de los grupos habilitados para el comando
                        comandos_habilitados.append(comando)

                if comandos_habilitados:
                    return f"Usuario {userid} puede ejecutar los siguientes comandos: {', '.join(comandos_habilitados)}"
                return f"Usuario {userid} no tiene comandos disponibles para ejecutar."
            
            return f"Usuario {userid} no existe en la base de miembros."
