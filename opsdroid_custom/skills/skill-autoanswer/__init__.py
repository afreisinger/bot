import redis
import random
import logging
import re
import httpx
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

def normalize_user(user: str) -> str:
    return re.sub(r'[^a-z0-9]+', '_', user.lower()).strip('_')

def get_effective_user(message):
    """
    Devuelve un identificador estable de usuario.
    """
    if message.user:
        return str(message.user)
    if message.connector.name == "websocketmod":
        return normalize_user("FREISINGER, ADRIAN GUSTAVO")
    return "unknown"


async def ask_ollama_http(prompt: str, model: str = "llama3.2") -> str:
    """Pregunta a Ollama usando su API HTTP /v1/completions."""
    url = f"http://ollama:11434/v1/completions"
    
    full_prompt = (
    "You are a helpful assistant. Only answer in spanish.\n\n"
    f"User say: {prompt}"
    )
    payload = {
        "model": model,
        "prompt": full_prompt,
        "max_tokens": 150
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("text", "").strip()
            return "No obtuve respuesta de Ollama."
    except Exception as e:
        _LOGGER.error(f"Error llamando a Ollama HTTP: {e}")
        return "Error al procesar la solicitud."


class SpanishAutoResponse(Skill):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.greetings = SPANISH_GREETINGS
        redis_cfg = self.config.get("redis", {})
        
        # Conexión persistente a Redis usando tus parámetros
        self.redis_client = redis.StrictRedis(
            host=redis_cfg.get("host", "localhost"),
            port=int(redis_cfg.get("port", 6379)),
            password=redis_cfg.get("password"),
            db=int(redis_cfg.get("database", 0)),
            decode_responses=True
        )

    async def handle_auto_answer(self, message):
        """Gestiona el saludo automático con rate-limiting por usuario."""
                
        effective_user = get_effective_user(message)
        autoanswer_key = f"autoanswer:{normalize_user(effective_user)}"
        
        # El comando EXISTS devuelve 1 si la clave existe
        if self.redis_client.exists(autoanswer_key):
            _LOGGER.info(f"{effective_user} TIENE autoanswer")
            greeting = random.choice(self.greetings)
            await message.respond(greeting)
            #await safe_respond(message, greeting)            
        else:
            _LOGGER.info(f"Usuario {effective_user} NO TIENE autoanswer")
           
            ollama_key = f"ollama:{normalize_user(effective_user)}"
                       
            if self.redis_client.exists(ollama_key):
                _LOGGER.info(f"Usuario {effective_user} TIENE autoanswer ollama")
                
                n = int(self.redis_client.get(ollama_key))
                
                # al cambiar la logica clave vacia no existe, por lo que hay que manejarlo distinto
                #n_bytes = self.redis_client.get(ollama_key)
                #n = int(n_bytes) if n_bytes else 0
                
                _LOGGER.info(f"Ya he contestado a {effective_user} {n} veces")
                self.redis_client.set(ollama_key, n+1, ex=86400)
                if n > 10:
                    _LOGGER.info(f"Ya he contestado demasiado a {effective_user}")
                    await message.respond("He respondido muchas veces hoy, por favor espera a mañana para más respuestas.")
                    #await safe_respond(message, "He respondido muchas veces hoy, por favor espera a mañana para más respuestas.")
                    return
                
                answer = await ask_ollama_http(message.text, model="llama3.2")
                _LOGGER.info(answer)
                await message.respond(answer)
                #await safe_respond(message, answer)
            else:
                _LOGGER.info(f"Usuario {effective_user} no tiene autoanswer ollama")

    
    async def handle_vacaciones(self, message):
        """Gestiona el mensaje de licencia con rate-limiting por sala y día."""
        key_vacaciones = "vacaciones" 
        
        effective_user = get_effective_user(message)
        
        if self.redis_client.exists(key_vacaciones):
            
            fecha_regreso = self.redis_client.get(key_vacaciones)
            _LOGGER.info(f"Vacaciones activas hasta {fecha_regreso}")

            today_str = datetime.today().strftime('%Y-%m-%d')
            # Generamos una clave única para la sala y el día actual
            sent_key = f"lock:vacaciones:{today_str}:{normalize_user(effective_user)}"

            if not self.redis_client.exists(sent_key):
                await message.respond(f"¡Buenas! Estoy de licencia hasta el {fecha_regreso}.")
                # El bloqueo expira en 24 horas (86400 seg)
                self.redis_client.set(sent_key, "1", ex=86400)
            else:
                _LOGGER.info(f"Ya se notificó de las vacaciones en la sala {effective_user} hoy.")

    @match_regex(r'.*', case_sensitive=False)
    async def proxy_handler(self, message):
        """Punto de entrada principal para procesar y redirigir mensajes."""
        try:
            _LOGGER.info(f"Procesando mensaje:\n%r {message}")
            
            connector_name = str(message.connector.name)
            userid = str(message.user) if message.user else "unknown"
            target = str(message.target)
            sender = str(message.user)
            text = str(message.text)
            joined_members = 100
            effective_user = get_effective_user(message)
            
            _LOGGER.info(
            "MSG | connector=%s | target=%s | sender=%s | effective_user=%s | userid=%s | members=%s | text=%r",
            connector_name,
            target,
            sender,
            effective_user,
            userid,
            joined_members,
            text
        )
                
            # Lógica para mensajes provenientes de WebSocket           
            if connector_name == "websocketmod":
                await self.handle_vacaciones(message)
                await self.handle_auto_answer(message)
                return

            # Lógica para mensajes provenientes de Matrix
            if connector_name == "matrixmod":
                conn = message.connector
                jm = await conn.connection.joined_members(target)
                _LOGGER.info(f"Room {target} has {len(jm.members)} joined members.")
                joined_members = len(jm.members)

                
                # Solo procesar respuestas automáticas en chats privados o grupos pequeños
                if len(jm.members) < 4:
                    await self.handle_vacaciones(message)
                    await self.handle_auto_answer(message)


        except Exception as e:
            _LOGGER.error(f"Error en el procesamiento del mensaje: {e}")
            return