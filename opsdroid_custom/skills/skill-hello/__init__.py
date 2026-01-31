from opsdroid.skill import Skill
from opsdroid.matchers import match_regex


class HelloSkill(Skill):

    @match_regex(r"^hello$")
    async def hello(self, event):
        await event.respond("👋 Hola! Opsdroid está vivo.")
