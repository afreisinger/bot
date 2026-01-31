from opsdroid.skill import Skill
from opsdroid.matchers import match_rasanlu
from voluptuous import Required
import asyncio
import json
import logging
import random
from datetime import datetime
_LOGGER = logging.getLogger(__name__)

saludo = ["Buenas","Hola","Aloooo"]
despedida = ["Chau","Nos vemos","Adios!"]

class MySkill(Skill):
    @match_rasanlu('saludo')
    async def hello(self, message):
        """Replies to user when any 'saludo' intent is returned by Rasa NLU"""
        from utils import Utils 
        
        response = random.choice(saludo)
        if Utils.is_websocket(message):
            encoded_message = Utils.encode_base64(response)
            await message.respond(encoded_message)
        else:
            await message.respond(response)
        
        #await message.respond(response)
        _LOGGER.info(f"Responded with greeting: {response}")

    
    @match_rasanlu('despedida')
    async def bye(self, message):
        """Replies to user when any 'despedida' intent is returned by Rasa NLU"""
        from utils import Utils 
        response = random.choice(despedida)
        if Utils.is_websocket(message):
            encoded_message = Utils.encode_base64(response)
            await message.respond(encoded_message)
        else:
            await message.respond(response)
        
        _LOGGER.info(f"Responded with farewell: {response}")
