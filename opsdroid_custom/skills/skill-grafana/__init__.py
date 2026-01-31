import json
import base64
import logging

from aiohttp.web import Request

from opsdroid.events import Message, Image, File
from opsdroid.matchers import match_webhook
from opsdroid.skill import Skill 
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



def getImage(url, filename):
    import requests
    if url != "": 
        try:
            r = requests.get(url, stream = True, timeout=8, verify=False)
            _LOGGER.info(f"r {r}")

            if r.status_code == 200:
                #image = r.content
                #_LOGGER.info(f"getImage image {image}")
                image = base64.b64encode(r.content).decode('utf-8')
                _LOGGER.info(f"Returning image in Base64 {image}")
                return image, filename
                #_LOGGER.info(f"getImage image in Base64 {image}")
            else:
                _LOGGER.info("Status dif 200 downloading image")
                filename = "girasol.jpg"
        except requests.exceptions.Timeout as e:
            _LOGGER.info("Exception ocurred: Timeout")
            filename = "girasol.jpg"
        except requests.exceptions.ConnectionError as e:
            _LOGGER.info("Exception ocurred: Max Retries")
            filename = "girasol.jpg"
       
        if "girasol.jpg" == filename:
            image = getLocalImage(filename)

        _LOGGER.info(f"getImage filename: {filename}")

    else:
        _LOGGER.info("URL = '' ")
        filename = "girasol.jpg"
        image = getLocalImage(filename)
    return image, filename

def getLocalImage(filename):  
    with open(filename,"rb") as f:
        data = f.read()
        _LOGGER.info("Image copied")
    return(data)



def validateParameters(data, tipo):
    if ("alerts" not in data ):              
        _LOGGER.error(f"Not a valid alert.")
        return False
    
    if (len(data["alerts"]) == 0 ): 
        _LOGGER.error(f"Not a valid alert length.")
        return False
    
    if ("annotations" not in data["alerts"][0] or data["alerts"][0]["annotations"] == ""):              
        _LOGGER.error(f"annotation no esta en la posicion data['alerts'][0] o es un string vacio.")
        return False
    
    annotations = data["alerts"][0]["annotations"]
    
    if ("mails" not in annotations and "matrix" not in annotations and "telegrams" not in annotations):
        _LOGGER.error(f"Not a valid target. No estan definidos los receptores.")
        return False

    existe_one_reciever_flag = 0
    if ("mails" not in annotations or annotations["mails"] == ""):
        _LOGGER.error(f"Not a valid target. No esta definido mail.")
    else:
        existe_one_reciever_flag = 1

    if (existe_one_reciever_flag == 0 and ("matrix" not in annotations or annotations["matrix"] == "" )):
        _LOGGER.error(f"Not a valid target. No esta definido matrix.")
    else:
        existe_one_reciever_flag = 1
        
    if (existe_one_reciever_flag == 0 and ("telegrams" not in annotations or annotations["telegrams"] == "")):
        _LOGGER.error(f"Not a valid target. No esta definido telegram.")
    else:
        existe_one_reciever_flag = 1


    if existe_one_reciever_flag == 0:
        _LOGGER.error(f"Not a valid target. No esta definido ninguno.")
        return False
    
    if ("description" not in annotations or annotations["description"] == ""):
        _LOGGER.error(f"Not a valid description.")
        return False

    if (tipo == "msj" and ("Message" not in annotations or annotations["Message"] == "")):
        _LOGGER.error(f"Not a valid message url.")
        return False

    if (tipo == "img" and ("image_url" not in annotations or annotations["image_url"] == "")):
        _LOGGER.error(f"Not a valid image url.")
        return False

    return True



def modificar_emails(cadena):
    emails = cadena.split(',')
    for i in range(len(emails)):
        email = emails[i].strip()  
        if not email.endswith('@afip.gob.ar'):
            emails[i] = email + '@afip.gob.ar'
    return ', '.join(emails)



class grafana(Skill):

    def __init__(self, opsdroid, config):
        import sys
        super().__init__(opsdroid, config)
        sys.path.append("/modules")
        self.token = config.get("token")

    @match_webhook("alert")
    async def alert(opsdroid, config, message):
        if type(message) is not Message and type(message) is Request:
            # Capture the request json data and set message to a default message
            request = await message.json()
            _LOGGER.debug(request)
            connector = opsdroid.default_connector
            room = config.get("room", connector.default_room)
            message = Message("", None, room, connector)
            #            await self.opsdroid.send(Message(text=text,connector="mailconnector",target=target))
            await message.opsdroid.send(Message(text=text,connector=connector,target=target))

            if "imageUrl" in request:
                await message.respond(request["imageUrl"])


    @match_webhook("enviar_msg")
    async def enviar_msg(self, event: Request):
        if validateTOKEN(event, self):
            data = await event.json()
            #_LOGGER.info(data)

            if not validateParameters(data, "msj"):
                return web.Response(status=401, text="Error. A parameter is not valid.")

            # connector = data["alerts"][0]
            annotations = data["alerts"][0]["annotations"]
            msg = annotations["Message"]
            desc = annotations["description"]
            #dashbURL = connector["dashboardURL"]
            #panelURL = connector["annotations"]["panelURL"]

            error = {}

            if ("mails" in annotations):
                #mail = annotations["mails"]
                mail = modificar_emails(annotations["mails"])
                if mail != "":
                    try: 
                        _LOGGER.info(f"Sending to {mail} message \"{msg}\" on mail connector")
                        await self.opsdroid.send(Message(text=msg,connector="mailconnector",target=mail))
                    except Exception as e:
                        _LOGGER.error(f"Error decoding or sending the file: {str(e)}")
                        error["mail"] = "mail"

            if ("matrix" in annotations):
                matrix = annotations["matrix"]
                if matrix !=  "":
                    receivers = matrix.split(",")
                    try:
                        for receiver in receivers:
                            _LOGGER.info(f"Sending to {matrix} message \"{msg}\" on matrix connector")
                            await self.opsdroid.send(Message(text=msg,connector="matrixmod",target=receiver))
                    except Exception as e:
                        _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                        error["matrix"] = "matrix"

            if ("telegrams" in annotations):
                telegram = annotations["telegrams"]
                if telegram !=  "":
                    try: 
                        receivers = telegram.split(",")
                        for receiver in receivers:
                            _LOGGER.info(f"Sending to {telegram} message \"{msg}\" on telegram connector")
                            await self.opsdroid.send(Message(text=msg, connector="telegrampost", target=receiver))
                    except Exception as e:
                        _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                        error["telegram"] = "telegram"

            #_LOGGER.info("msg: "+ str(msg))
            #_LOGGER.info("desc: "+ str(desc))
            #_LOGGER.info("connector: mail: "+ str(mail))
            #_LOGGER.info("connector: telegran: "+ str(telegram))
            #_LOGGER.info("connector: matrix: "+ str(matrix))
            #_LOGGER.info("panelURL: "+ str(panelURL)) 

        else:
            return web.Response(status=401, text="Error in Authorization.")


    @match_webhook("enviar_imagen")
    async def enviar_imagen(self, event: Request):
        if validateTOKEN(event, self):
            data = await event.json()
            if not validateParameters(data, "img"):
                return web.Response(status=401, text="Error. A parameter is not valid.")

            #connector = data["alerts"][0]
            annotations = data["alerts"][0]["annotations"]
            desc = annotations["description"]
            urlImage = annotations["image_url"]
            #panelURL = annotations["panelURL"]
            img_tipo = urlImage.split(".")[-1]

            if ("Message" in annotations and annotations["Message"] != ""): 
                msg = annotations["Message"]
            else:
                msg = ""

            try:                                        
                image_data, xxx = getImage(urlImage, "prueba.jpg")
                image_data = base64.b64decode(image_data)
            except Exception as e:
                _LOGGER.error(f"Error decoding or sending the message: {str(e)}")
                return web.Response(status=401, text="Error decoding or sending the message.")

            error = {}

            if ("mails" in annotations):
                #mail = annotations["mails"]
                mail = modificar_emails(annotations["mails"])
                if mail != "":
                    _LOGGER.info(f"Sending image to {mail} in mail connector.")     

                    try:
                        _LOGGER.info(f"Sending image to {mail} on mail connector.")
                        await self.opsdroid.send(Image(connector="mailconnector", target=mail, file_bytes=image_data, name=img_tipo))
                    except Exception as e:
                        _LOGGER.error(f"Error decoding or sending the file: {str(e)}")
                        error["mail"] = "mail"

            if ("telegrams" in annotations):
                telegram = annotations["telegrams"]
                if telegram !=  "":
                    receivers = telegram.split(",")
                    for receiver in receivers:
                        try:
                            _LOGGER.info(f"Sending image to {telegram} on telegram connector.")
                            await self.opsdroid.send(Image(connector="telegrampost", target=receiver, file_bytes=image_data))
                            if msg != "":
                                await self.opsdroid.send(Message(text=msg, connector="telegrampost", target=receiver))
                        except Exception as e:
                            _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                            error["telegram"] = "telegram"

            if ("matrix" in annotations):
                matrix = annotations["matrix"]
                if matrix !=  "":
                    receivers = matrix.split(",")
                    for receiver in receivers:
                        try:
                            _LOGGER.info(f"Sending image to {matrix} on matrix connector.")
                            await self.opsdroid.send(Image(connector="matrixmod", target=receiver, file_bytes=image_data))
                            if msg != "":
                                await self.opsdroid.send(Message(text=msg, connector="matrixmod", target=receiver))
                        except Exception as e:
                            _LOGGER.error(f"Error while sending file/msg via telegram: {e}")
                            error["matrix"] = "matrix"

            if len(error) > 0:
                return web.Response(status=401, text=f"Error sending file via: {error}.")

        else:
            return web.Response(status=401, text="Error in Authorization.")




    """
    @match_webhook("enviar_archivo")
    async def enviar_archivo(self, event: Request):
        if validateTOKEN(event, self):
            data = await event.json()
            _LOGGER.info(data)
            try:
                connector = data["alerts"][0]
                panelURL = connector["annotations"]["panelURL"]
                msg = connector["annotations"]["Message"]
                desc = connector["annotations"]["description"]
                mail = connector["annotations"]["mails"]
                matrix = connector["annotations"]["matrix"]
                telegram = connector["annotations"]["telegrams"]
                _LOGGER.info("msg: "+ str(msg))
            except Exception as e:
                _LOGGER.error(f"Error decoding or sending the message: {str(e)}")
                return

            if mail != "":
                _LOGGER.info(f"Sending to {mail} message {msg} on {connector}")
                await self.opsdroid.send(File(connector="mailconnector", target=mail, file_bytes=data["archivo"], name=msg))

            if telegram !=  "": 
                receivers = telegram.split(",")
                for receiver in receivers:
                  _LOGGER.info(f"Sending to {receiver} message {msg} on {connector}")
                  await self.opsdroid.send(Message(text=msg, connector="telegrampost", target=receiver))

            if matrix !=  "":
                receivers = matrix.split(",")
                for receiver in receivers:
                  _LOGGER.info(f"Sending to {matrix} message {msg} on {connector}")
                  await self.opsdroid.send(Message(text=msg, connector="matrixmod", target=receivers))
   """



