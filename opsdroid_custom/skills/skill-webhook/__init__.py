
import base64
from aiohttp.web import Request
import traceback
from opsdroid.skill import Skill
from opsdroid.matchers import match_webhook
from opsdroid.events import Message, Image, File
import logging

from voluptuous import Required

from aiohttp import web


_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    Required("token"): str,
}


def validateTOKEN(event, self):
    from aiohttp import web
    auth_header = event.headers.get("Authorization")
    #_LOGGER.info(auth_header)
        
    if not auth_header:
        _LOGGER.error("Missing Authorization header.")
        #return web.Response(status=401, text="Unauthorized: Missing Authorization header.")
        return False

    token = auth_header.split(" ")[1] if "Bearer" in auth_header else None
    #_LOGGER.info(token)
    
    if not token:
        _LOGGER.error("Invalid Authorization header format. Bearer token missing.")
        #return web.Response(status=401, text="Unauthorized: Invalid Authorization header format.")
        return False
    
    bearer_token = self.token
    if str(bearer_token) == str(token):
        return True
    else:
        return False


def validateParameters(data, tipo):
    if (("connector" not in data) or (data["connector"] != "mail" and data["connector"] != "matrix" and data["connector"] != "telegram")):
        _LOGGER.error(f"Not a valid connector.")
        return False
    if ("target" not in data or data["target"] == ""):
        _LOGGER.error(f"Not a valid target.")
        return False
    if ("nombre" not in data or data["nombre"]  == ""):
        _LOGGER.error(f"Not a valid nombre.")
        return False
    if ("tipo" not in data or data["tipo"]  == ""):
        _LOGGER.error(f"Not a valid tipo.")
        return False
    if tipo == "msg":
        if "text" not in data or data["text"] == "":
            _LOGGER.error(f"Not a valid text msg.")
            return False
    if tipo == "img":
        if "image" not in data or data["image"] == "":
            _LOGGER.error(f"Not a valid image.")
            return False
    if tipo == "file":
        if "archivo" not in data or data["archivo"] == "":
            _LOGGER.error(f"Not a valid file.")
            return False
    return True


class WebhookSkill(Skill):

    def __init__(self, opsdroid, config):
        import sys
        super().__init__(opsdroid, config)
        sys.path.append("/modules")
        self.token = config.get("token")



    @match_webhook('enviarmsg')
    async def mywebhookskill(self, event: Request):
        _LOGGER.debug("Got hit!")
        # Capture the post data
        if validateTOKEN(event, self):
            data = await event.json()
            data["nombre"] = "dummy"
            data["tipo"] = "dummy"

            if not validateParameters(data, "msg"):
                return web.Response(status=401, text="Error. A parameter is not valid.")

            connector = data["connector"]
            target = data["target"].replace(" ", "")
            text = data["text"]

            if connector == "mail":
                _LOGGER.info(f"Sending to {target} message {text} on {connector}")
                await self.opsdroid.send(Message(text=text,connector="mailconnector",target=target))
            elif connector ==  "telegram":
                _LOGGER.info(f"Sending to {target} message {text} on {connector}")
                await self.opsdroid.send(Message(text=text,connector="telegrampost",target=target))
            elif connector ==  "matrix":
                _LOGGER.info(f"Sending to {target} message {text} on {connector}")
                await self.opsdroid.send(Message(text=text,connector="matrixmod",target=target))
        else :
            return web.Response(status=401, text="Error. Failed validating token.")



    @match_webhook('enviarimagen')
    async def enviarimagen(self, event: Request):
        _LOGGER.debug("Got hit!")
        # Capture the post data
        if validateTOKEN(event, self):
            data = await event.json()
        
            if not validateParameters(data, "img"):
                return web.Response(status=401, text="Error. Not a valid parameter.")
        
            connector = data["connector"]
            target = data["target"].replace(" ", "")
            text = data["text"]
            tipo = data["tipo"]
            nombre = data["nombre"]
            image_base64 = data["image"]
            image_data = base64.b64decode(image_base64)

            if connector == "mail":
                _LOGGER.info(f"Sending to {target} message {data['text']} on {connector}")
                try:
                    await self.opsdroid.send(Image(connector="mailconnector", target=target, file_bytes=image_data))
                except Exception as e:
                    _LOGGER.error(f"Error decoding or sending the image: {str(e)}")
                    return

            if connector ==  "telegram":
                receivers = target.split(",")
                for receiver in receivers:
                  _LOGGER.info(f"Sending to {receiver} message {text} on {connector}")
                  await self.opsdroid.send(Image(connector="telegrampost", target=receiver, file_bytes=image_data))
                  await self.opsdroid.send(Message(connector="telegrampost", target=receiver, text=text))

            if connector ==  "matrix":
                receivers = target.split(",")
                for receiver in receivers:
                  _LOGGER.info(f"Sending to {receiver} message \"{text}\" on matrix connector")
                  await self.opsdroid.send(Image(connector="matrixmod", target=receiver, file_bytes=image_data))
                  await self.opsdroid.send(Message(text=text, connector="matrixmod", target=receiver))

        else :
            return web.Response(status=401, text="Error. Failed validating token.")

                
        
    @match_webhook('enviararchivo')
    async def enviararchivo(self, event: Request):
        _LOGGER.debug("Got hit!")
        # Capture the post data
        if validateTOKEN(event, self):
            data = await event.json()

            if not validateParameters(data, "file"):
                return web.Response(status=401, text="Error. A parameter is not valid.")

            connector = data["connector"]
            target = data["target"].replace(" ", "")
            text = data["text"]
            nombre = data["nombre"]
            tipo = data["tipo"]
            file_base64 = data["archivo"]
            file_data = base64.b64decode(file_base64)

            error = {}

            if connector == "mail":
                _LOGGER.info(f"Sending to {target} message {data['text']} on {connector}")
                try:
                    #image_data = base64.b64decode(file_base64)
                    f = File(connector="mailconnector", name=nombre, target=target, file_bytes=file_data)
                    await self.opsdroid.send(f)
                except Exception as e:
                    _LOGGER.error(f"Error decoding or sending the file: {str(e)}")
                    _LOGGER.error(traceback.format_exc())
                    error["mail"] = "mail"
                    #return

            if connector ==  "telegram":
                receivers = target.split(",")
                for receiver in receivers:
                    try:
                        _LOGGER.info(f"Sending to {receiver} message {text} on {connector}")
                        await self.opsdroid.send(File(connector="telegrampost", name=nombre, target=receiver, file_bytes=file_data))
                        await self.opsdroid.send(Message(connector="telegrampost", target=receiver, text=text))
                    except Exception as e:
                        _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                        _LOGGER.error(traceback.format_exc())
                        error["telegram"] = "telegram"
                        #return web.Response(status=401, text="Error. Failed validating token.")

            if connector ==  "matrix":
                receivers = target.split(",")
                for receiver in receivers:
                    try:
                        _LOGGER.info(f"Sending to {receiver} message \"{text}\" on matrix connector")
                        await self.opsdroid.send(File(connector="matrixmod", name=nombre, target=receiver, file_bytes=file_data))
                        await self.opsdroid.send(Message(text=text, connector="matrixmod", target=receiver))
                    except Exception as e:
                        _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                        _LOGGER.error(traceback.format_exc())
                        error["matrix"] = "matrix"
                        #return web.Response(status=401, text="Error. Failed validating token.")
            if len(error) > 0:
                return web.Response(status=401, text=f"Error sending file via: {error}.")


        else :
            return web.Response(status=401, text="Error. Failed validating token.")



