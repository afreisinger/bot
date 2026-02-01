import redis
import random
import logging
import re
import httpx
import json
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

MAX_MEMORY_MESSAGES = 10  # ventana de contexto

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


def load_memory(redis_client, user):
    key = f"memory:{user}"
    raw = redis_client.get(key)
    if not raw:
        return []
    try:
        return json.loads(raw)
    except Exception:
        return []

def save_memory(redis_client, user, messages):
    key = f"memory:{user}"
    redis_client.set(
        key,
        json.dumps(messages[-MAX_MEMORY_MESSAGES:]),
        ex=86400  # 1 día
    )





async def ask_ollama_http(prompt: str, memory: str, model: str = "llama3.2") -> str:
    """Pregunta a Ollama usando su API HTTP /v1/completions."""
    url = f"http://ollama:11434/v1/completions"
    
    conversation = ""
    for m in memory:
        role = "Usuario" if m["role"] == "user" else "Asistente"
        conversation += f"{role}: {m['content']}\n"

    full_prompt = (
    "Sos un asistente útil. Respondé solo en español.\n\n"
    f"{conversation}"
    f"Usuario: {prompt}\n"
    "Asistente:"
    )
    
    payload = {
        "model": model,
        "prompt": full_prompt,
        "max_tokens": 200
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, timeout=30)
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
                
                n = int(self.redis_client.get(ollama_key) or 0)
            
                _LOGGER.info(f"Ya he contestado a {effective_user} {n} veces")
                self.redis_client.set(ollama_key, n+1, ex=86400)
                if n > 10:
                    _LOGGER.info(f"Ya he contestado demasiado a {effective_user}")
                    await message.respond("He respondido muchas veces hoy, por favor espera a mañana para más respuestas.")
                    #await safe_respond(message, "He respondido muchas veces hoy, por favor espera a mañana para más respuestas.")
                    return
                
                # Cargar memoria previa
                memory = load_memory(self.redis_client, normalize_user(effective_user))
                # Rsponse de Ollama
                answer = await ask_ollama_http(message.text, memory, model="llama3.2")
                # Actualizar memoria
                memory.append({"role": "user", "content": message.text})
                memory.append({"role": "assistant", "content": answer})

                save_memory(self.redis_client, normalize_user(effective_user), memory)

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