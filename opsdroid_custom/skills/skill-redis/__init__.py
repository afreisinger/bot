from opsdroid.skill import Skill
from opsdroid.matchers import match_regex
from voluptuous import Required
from opsdroid.events import Message
import redis
import logging

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    Required("host"): str,
    Required("port"): str
}


class redisskill(Skill):
    def __init__(self, opsdroid, config):
        super(redisskill, self).__init__(opsdroid, config)
        import sys

        self.redis_host = config.get('host')  # Redis host from config
        self.redis_port = config.get('port')  # Redis port from config
        self.client = redis.Redis(host=self.redis_host, port=self.redis_port, password = config.get('password'))
        
        sys.path.append("/modules")



    @match_regex(r'^!redis set (.+) (.+)$')
    async def set_value(self, event):
        """Store a value in Redis."""
        key, value = event.regex.group(1), event.regex.group(2)
        self.client.set(key, value)
        await event.respond(f'Value set for {key}: {value}')
    
    @match_regex(r'^!redis get (.+)$')
    async def get_value(self, event):
        """Retrieve a value from Redis."""
        key = event.regex.group(1)
        value = self.client.get(key)
        if value:
            await event.respond(f'The value for {key} is: {value.decode()}')
        else:
            await event.respond(f'No value found for {key}')
