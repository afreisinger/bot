import re
import logging
from urllib.parse import urlparse

#from matrix_client.errors import MatrixRequestError

#from opsdroid.connector.matrix import ConnectorMatrix
#from opsdroid.connector.matrix.events import MatrixStateEvent
from opsdroid.events import Message, OpsdroidStarted, UserInvite, JoinRoom
from opsdroid.matchers import match_event, match_regex
from opsdroid.skill import Skill

try:
    from opsdroid.events import PinMessage, UnpinMessage

    PINNED_MESSAGES = True
except Exception:
    PINNED_MESSAGES = False
    PinMessage = UnpinMessge = object


_LOGGER = logging.getLogger(__name__)

"""
post-pyastro TODO:

* Use room state to get the default jitsi URL
* Use previous state to ensure the right conf gets removed (support multiple widgets)
* Allow non-matrix mode
"""


class MatrixAutoJoin(Skill):
    """
    This skill can generate a Jitsi call URL and post it to the room.

    If the matrix connector is configured and the message comes in on the
    matrix connector, as well as generating the URL it will also post a v2
    Jitsi call widget for Riot support.

    By default the URL for the call will be the room name, this is only
    supported for slack and matrix, otherwise a random name will be used.

    There is also a "bridged" mode for use in a room which is listening on both
    slack and matrix. In this mode the skill only listens for commands from the
    matrix connector, and only sends messages to slack (to enable pinned
    messages), but also sends widgets to matrix.
    """

    def __init__(self, opsdroid, config):
        super().__init__(opsdroid, config)
        self.matrix_only = config.get("listen_matrix_only", False)
        self.join_when_invited = config.get("join_when_invited", False)



    def process_message(self, message):
        if self.matrix_only and not isinstance(message.connector, ConnectorMatrix):
            return False
        return True



    @match_event(UserInvite)
    async def on_invite_to_room(self, invite):
        """
        Join all rooms on invite.
        """
        _LOGGER.info(f"Got room invite for {invite.target}.")
        if self.join_when_invited:
            _LOGGER.debug(f"Joining room from invite.")
            await invite.respond(JoinRoom())

