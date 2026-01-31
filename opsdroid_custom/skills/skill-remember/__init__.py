from opsdroid.skill import Skill
from opsdroid.matchers import match_regex
from voluptuous import Required

class Remember(Skill):
    def __init__(self, opsdroid, config):
        super(Remember, self).__init__(opsdroid, config)
        import sys
        sys.path.append("/modules")

    @match_regex(r'remember (.*)')
    async def remember(self, message):
        from utils import Utils
        remember = message.regex.group(1)
        await self.opsdroid.memory.put("remember_this", remember)
        if Utils.is_websocket(message):
            await message.respond(Utils.encode_base64("OK I'll remember that"))
        else:
            await message.respond("OK I'll remember that")

    @match_regex(r'remind me')
    async def remind_me(self, message):
        from utils import Utils
        information = await self.opsdroid.memory.get("remember_this")
        if Utils.is_websocket(message):
            await message.respond(Utils.encode_base64(information))
        else:
            await message.respond(information)

    @match_regex(r'forget it')
    async def forget_it(self, message):
        from utils import Utils
        await self.opsdroid.memory.delete("remember_this")
        if Utils.is_websocket(message):
            await message.respond(Utils.encode_base64("Ok I'll forget it"))
        else:
            await message.respond("Ok I'll forget it""Está bien, lo olvidaré")