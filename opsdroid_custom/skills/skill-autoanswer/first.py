# import logging
# import random
# import redis
# import os
# from datetime import datetime
# from opsdroid.matchers import match_regex
# from opsdroid.events import Message

# _LOGGER = logging.getLogger(__name__)

# spanish_greetings = [
#     "Hola! Estoy fuera de oficina.",
#     "¡Buenas! En este momento no puedo responder.",
#     "Saludos, estoy de vacaciones.",
#     "Hola, estoy ocupado/a, te responderé luego."
# ]

# def get_page(url):
#     return "Dummy page content"

# def add_two_numbers(a, b):
#     return a + b

# def subtract_two_numbers(a, b):
#     return a - b

# async def AutoAnswer(message):
#     host = os.environ.get("REDIS_HOST", "redis")
#     port = int(os.environ.get("REDIS_PORT", 6379))
#     password = os.environ.get("REDIS_PASSWORD", "pepe00")
    
#     # Nota: redis.Redis() es sincrónico, bloqueará el loop brevemente.
#     with redis.Redis(host=host, port=port, password=password, db=0) as r:
#         user_key = str(message.user)
#         auto_answer = r.exists(user_key)
#         if auto_answer != 0:
#             _LOGGER.info(f"Usuario {user_key} TIENE autoanswer")
#             random_greeting = random.choice(spanish_greetings)
#             await message.respond(random_greeting)
#         else:
#             _LOGGER.info(f"Usuario {user_key} no tiene autoanswer")
#             #uso ollama ?
#             ollama_key = str("ollama_" + user_key)
#             ollama_answer = r.exists(ollama_key)
#             #ollama.create(model='jg', from_='comu:8b', system="Sos una persona muy cordial, pero concisa. Respondes a las preguntas puntuales y nada mas. Te encontras de buen humor y con bastante trabajo. Cualquier pregunta laboral respondes que tenes que consultarlo con tu jefe.")
#             if ollama_answer != 0:
#                 n_bytes = r.get(ollama_key)
#                 n = int(n_bytes.decode("utf-8")) if n_bytes else 0
                
#                 _LOGGER.info(f"Ya he contestado a {message.user} {n} veces")
#                 r.set(ollama_key, n+1, ex=86400)
#                 if n > 10:
#                     _LOGGER.info(f"Ya he contestado demasiado a {message.user}")
#                     return
#                 _LOGGER.info(f"Usuario {user_key} TIENE autoanswer ollama")
                
#                 try:
#                     import ollama
#                     from ollama import ChatResponse
                    
#                     # Hardcoded host from example, adjusting if needed
#                     client = ollama.Client(
#                         host='http://192.168.100.200:11434',
#                     )
#                     response: ChatResponse = client.chat(model='comu:7b',
#                                                          tools=[get_page,add_two_numbers, subtract_two_numbers],
#                                                          messages=[
#                         {
#                             'role': 'system',
#                             'content': 'You are a helpful assistant. Only answer in spanish',
#                         },

#                         {
#                             'role': 'user',
#                             'content': message.text,
#                         },
#                     ])
#                 # print(response['message']['content'])
#                 # or access fields directly from the response object
#                 # print(response.message.content)
#                     _LOGGER.info(response)
#                     await message.respond(response.message.content)
#                 except Exception as e:
#                     _LOGGER.error(f"Error con Ollama: {e}")
#             else:
#                 _LOGGER.info(f"Usuario {user_key} no tiene autoanswer ollama")


# async def vacaciones(message):
#     host = os.environ.get("REDIS_HOST", "redis")
#     port = int(os.environ.get("REDIS_PORT", 6379))
#     password = os.environ.get("REDIS_PASSWORD", "pepe00")
    
#     with redis.Redis(host=host, port=port, password=password, db=0) as r:
#         anio = datetime.today().strftime('%Y')
#         dia = datetime.today().strftime('%d')
#         mes = datetime.today().strftime('%m')
#         room = message.target
#         vacas_key = "vacaciones"
#         vacas = r.exists(vacas_key)
#         if vacas != 0:
#             fecha_bytes = r.get(vacas_key)
#             fecha = fecha_bytes.decode("utf-8") if fecha_bytes else "??"
            
#             redis_key = "hello" + "-" + str(anio) + "-" + str(mes) + "-" + str(dia) + "-" + str(room)
#             sent = r.exists(redis_key)
#             if sent == 0:
#                 await message.respond(f"Buenas!! Estoy de licencia hasta el {fecha}.")
#                 r.set(redis_key, 1, ex=86400)
#             else:
#                 _LOGGER.info("Already sent hi...")
#         else:
#             _LOGGER.info("No estoy de vacas :C")


# @match_regex(r'.*', case_sensitive=False)
# async def proxy_text(opsdroid, config, message):
#     try:
#         text = str(message.text)
#         # _LOGGER.error(message)
#         sender = str(message.user)
#         target = str(message.target)
        
#         # message.connector might fail if mocking
#         try:
#             connector_name = str(message.connector.name)
#         except:
#             connector_name = "unknown"
            
#         joined_members = 100
#         if connector_name == "matrixmod":
#             try:
#                 conn = message.connector
#                 jm = await conn.connection.joined_members(target)

#                 _LOGGER.info(f"Room {target} has {len(jm.members)} joined members.")
#                 joined_members = len(jm.members)
#             except Exception as e:
#                 _LOGGER.warning(f"Failed to get joined members: {e}")

#         telegram_room = "141596784"

#         msg_log = f"{connector_name} - {target} - {sender} : {text}"
#         if connector_name == "matrixmod":
#             if joined_members < 3:
#                 await vacaciones(message)
#                 await AutoAnswer(message)

#             await opsdroid.send(Message(text=msg_log,
#                                         target=telegram_room,
#                                         connector="telegrampost"
#                                         )
#                                 )
#         if connector_name == "telegrampost":
#             text = str(message.text)
#             arr = text.split(" ",1)

#             if len(arr) > 1:
#                 target_room = arr[0]
#                 msg_content = arr[1]
#                 # _LOGGER.error(text)
                
#                 if target_room != "" and msg_content != "":
#                     await opsdroid.send(Message(text=msg_content,
#                                             target=target_room,
#                                             connector="matrixmod"
#                                             )
#                                     )
#     except Exception as e:
#         _LOGGER.error(f"Error in proxy_text: {e}")
#         return

# import logging
# from opsdroid.matchers import match_regex
# from opsdroid.events import Message

# _LOGGER = logging.getLogger(__name__)

# @match_regex(r'.*', case_sensitive=False)
# async def test_echo(opsdroid, config, message: Message):
#     _LOGGER.error(f"Test skill recibió mensaje: {message.text} de {message.user}")
#     await message.respond(f"AutoAnswer test: recibí tu mensaje '{message.text}'")

# import logging
# import random
# import os
# from opsdroid.matchers import match_regex
# from opsdroid.events import Message
# import aioredis

# _LOGGER = logging.getLogger(__name__)

# SPANISH_GREETINGS = [
#     "Hola! Estoy fuera de oficina.",
#     "¡Buenas! En este momento no puedo responder.",
#     "Saludos, estoy de vacaciones.",
#     "Hola, estoy ocupado/a, te responderé luego."
# ]

# # Crea conexión Redis global async
# async def get_redis():
#     redis_host = os.environ.get("REDIS_HOST", "redis")
#     redis_port = int(os.environ.get("REDIS_PORT", 6379))
#     redis_password = os.environ.get("REDIS_PASSWORD", "pepe00")
#     return await aioredis.from_url(f"redis://:{redis_password}@{redis_host}:{redis_port}/7", decode_responses=True)

# @match_regex(r'.*', case_sensitive=False)
# async def autoanswer(opsdroid, config, message: Message):
#     try:
#         r = await get_redis()
#         user_key = str(message.user)

#         exists = await r.exists(user_key)
#         if exists:
#             greeting = random.choice(SPANISH_GREETINGS)
#             _LOGGER.error(f"AutoAnswer: enviando saludo a {user_key}")
#             await message.respond(greeting)
#         else:
#             _LOGGER.info(f"AutoAnswer: {user_key} no tiene autoanswer")
#     except Exception as e:
#         _LOGGER.error(f"Error en AutoAnswer: {e}")
import redis
import random
import logging
from datetime import datetime
from opsdroid.skill import Skill
from opsdroid.matchers import match_regex
from opsdroid.events import Message

_LOGGER = logging.getLogger(__name__)

SPANISH_GREETINGS = [
    "Hola! Estoy fuera de oficina.",
    "¡Buenas! En este momento no puedo responder.",
    "Saludos, estoy de vacaciones.",
    "Hola, estoy ocupado/a, te responderé luego."
]

class SpanishAutoResponse(Skill):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.greetings = SPANISH_GREETINGS
        
        # Conexión persistente a Redis usando tus parámetros
        self.redis_client = redis.StrictRedis(
            host="redis", 
            port=6379, 
            password="pepe00", 
            db=0, 
            decode_responses=True
        )

    async def handle_auto_answer(self, message):
        """Gestiona el saludo automático con rate-limiting por usuario."""
        user_key = f"lock:autoanswer:{message.user}"
        
        # El comando EXISTS devuelve 1 si la clave existe (ya respondimos recientemente)
        if not self.redis_client.exists(user_key):
            _LOGGER.info(f"Usuario {message.user} no tiene bloqueo. Saludando...")
            greeting = random.choice(self.greetings)
            await message.respond(greeting)
            
            # Seteamos el bloqueo por 3600 segundos (1 hora)
            # Esto 'registra' que ya se envió el mensaje
            self.redis_client.set(user_key, "sent", ex=3600)
        else:
            _LOGGER.info(f"Ignorando saludo para {message.user} (bloqueo activo)")

    async def handle_vacaciones(self, message):
        """Gestiona el mensaje de licencia con rate-limiting por sala y día."""
        vacas_key = "vacaciones_status" # Clave que debes setear manualmente en Redis con la fecha
        
        if self.redis_client.exists(vacas_key):
            fecha_regreso = self.redis_client.get(vacas_key)
            today_str = datetime.today().strftime('%Y-%m-%d')
            # Generamos una clave única para la sala y el día actual
            sent_key = f"lock:vacas:{today_str}:{message.target}"

            if not self.redis_client.exists(sent_key):
                await message.respond(f"¡Buenas! Estoy de licencia hasta el {fecha_regreso}.")
                # El bloqueo expira en 24 horas (86400 seg)
                self.redis_client.set(sent_key, "1", ex=86400)
            else:
                _LOGGER.info(f"Ya se notificó de las vacaciones en la sala {message.target} hoy.")

    @match_regex(r'.*', case_sensitive=False)
    async def proxy_handler(self, message):
        """Punto de entrada principal para procesar y redirigir mensajes."""
        try:
            connector_name = message.connector.name
            target = message.target
            sender = message.user
            text = message.text

            # Lógica para mensajes provenientes de Matrix
            if connector_name == "matrixmod":
                conn = message.connector
                jm = await conn.connection.joined_members(target)
                
                # Solo procesar respuestas automáticas en chats privados o grupos pequeños
                if len(jm.members) < 3:
                    await self.handle_vacaciones(message)
                    await self.handle_auto_answer(message)

                # Reenvío a Telegram (Proxy)
                telegram_room = "141596784"
                forward_text = f"{connector_name} - {target} - {sender} : {text}"
                await self.opsdroid.send(Message(
                    text=forward_text,
                    target=telegram_room,
                    connector="telegrampost"
                ))

            # Lógica para responder desde Telegram hacia Matrix
            elif connector_name == "telegrampost":
                parts = text.split(" ", 1)
                if len(parts) > 1:
                    matrix_target = parts
                    reply_msg = parts[1]
                    await self.opsdroid.send(Message(
                        text=reply_msg,
                        target=matrix_target,
                        connector="matrixmod"
                    ))

        except Exception as e:
            _LOGGER.error(f"Error en el procesamiento del mensaje: {e}")