"""A connector for Telegram."""

import asyncio
import logging

# import aiohttp
import traceback

from opsdroid.connector import Connector, register_event
from opsdroid.events import File, Image, Message
from voluptuous import Required

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = {
    Required("username"): str,
    Required("password"): str,
    Required("popserver"): str,
    Required("popport"): int,
    Required("smtpserver"): str,
    Required("smtpport"): int,
    "update-interval": float,
    "default-user": str,
    "whitelisted-users": list,
    "enable": str,    
    "subject": str,
    "domain": str,
}


class ConnectorMail(Connector):
    """A connector the the char service Telegram."""

    def __init__(self, config, opsdroid=None):  # noqa: D107
        """Init the config for the connector."""
        super().__init__(config, opsdroid=opsdroid)
        _LOGGER.debug(_("Loaded Mail Connector"))

        self.name = "mailconnector"
        self.opsdroid = opsdroid
        self.latest_update = None
        self.listening = True
        self.enable = config.get("enable", "False")
        self.update_interval = config.get("update-interval", 60)
        self.session = None
        self._closing = asyncio.Event()
        self.loop = asyncio.get_event_loop()
        self.poptimeout = config.get("poptimeout", 60)
        self.smtptimeout = config.get("smtptimeout", 60)
        self.subject = config.get("subject", "Comubot le ha enviado un mensaje.")
        self.domain = config.get("domain", "afip.gob.ar")
        _LOGGER.error(f"self.enable:  {self.enable}")
        try:
            self.username = config.get("username")
            self.password = config.get("password")
            self.popserver = config.get("popserver")
            self.popport = config.get("popport")

            self.smtpserver = config.get("smtpserver")
            self.smtpport = config.get("smtpport")

        except (KeyError, AttributeError):
            _LOGGER.error(
                _(
                    "Unable to login: usernme, password or popserver, popport, smtpserver or smtpport is missing. Mail connector will be unavailable."
                )
            )

    async def _parse_message(self, response):
        import email
        import re

        """Handle logic to parse a received message.

        Since everyone can send a private message to any user/bot
        in Telegram, this method allows to set a list of whitelisted
        users that can interact with the bot. If any other user tries
        to interact with the bot the command is not parsed and instead
        the bot will inform that user that he is not allowed to talk
        with the bot.

        We also set self.latest_update to +1 in order to get the next
        available message (or an empty {} if no message has been received
        yet) with the method self._get_messages().

        Args:
            response (dict): Response returned by aiohttp.ClientSession.

        """
        _LOGGER.debug(response)
        mail_from = response["headers"]["From"]
        m = re.search("<(\w*)@afip\.gob\.ar>", mail_from)
        try:
            user_id = m.group(1)
        except:
            _LOGGER.info("No se pudo extraer user_id. No tiene dominio afip el remitente?")
            return
        _LOGGER.debug(f"Got user: {user_id}")
        #target = f"{user_id}@afip.gob.ar"
        target = f"{user_id}@{self.domain}"
        _LOGGER.debug(f"Setting target to : {user_id}")
        message = Message(
            text="\n".join(response["body"]),
            user=user_id,
            user_id=user_id,
            target=target,
            connector=self,
        )
        await self.opsdroid.parse(message)

    async def _get_messages(self):
        import email
        import poplib
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("AES256-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False

        ctx.load_default_certs()
        _LOGGER.debug(f"Trying to get messages from {self.popserver}:{self.popport}")
        _LOGGER.debug(f"Using  {self.username}:*********")
        M = poplib.POP3_SSL(host=self.popserver, port=self.popport, timeout=50, context=ctx)

        M.user(self.username)
        M.pass_(self.password)
        mlist = M.list()
        numMessages = len(mlist[1])
        for i in range(numMessages):
            single_mail = {}
            msgspec = bytes.decode(mlist[1][i], "utf-8")
            msgnum = int(msgspec.split(" ")[0])
            mail = M.retr(i + 1)
            headers = {}
            length = len(mail[1])
            print(length)
            counter = 0

            single_mail["body"] = []
            endheaders = False
            for j in mail[1]:
                # print(bytes.decode(M.retr(i+1)[1],"utf-8"))
                counter = counter + 1
                line = bytes.decode(j, "utf-8")

                # _LOGGER.debug(f"Line: {line}")
                # _LOGGER.debug(f"Len: {len(line)}")

                # print(f"{j} -> {line}")
                # print(f"{counter} -> {len}")
                if len(line) == 0:
                    endheaders = True
                    continue
                if endheaders == True:
                    single_mail["body"].append(line)
                else:
                    header = line.split(": ")[0]
                    value = ""
                    failed = False
                    try:
                        value = line.split(": ")[1]
                    except:
                        failed = True
                        headers[header_ant] += header
                        print(f"header: {header_ant} -> {header}")
                        pass
                    if failed == False:
                        header_ant = header
                        headers[header] = value
                    # print(f"Header: {header} -> {value}")
            single_mail["headers"] = headers
            print(f"Headers: {headers}")
            await self._parse_message(single_mail)
            dele = M.dele(msgnum)

            print(dele)
        quit = M.quit()
        _LOGGER.debug(quit)
        M.close()

    async def get_messages_loop(self):
        import asyncio

        """Listen for and parse new messages.

        The bot will always listen to all opened chat windows,
        as long as opsdroid is running. Since anyone can start
        a new chat with the bot is recommended that a list of
        users to be whitelisted be provided in config.yaml.

        The method will sleep asynchronously at the end of
        every loop. The time can either be specified in the
        config.yaml with the param update-interval - this
        defaults to 1 second.

        """
        while self.listening:
            await asyncio.sleep(self.update_interval)
            try:
                await self._get_messages()
            except Exception as e:
                _LOGGER.error("Could not get messages.")
                _LOGGER.error(f"{e}")
                _LOGGER.error(f"{e.with_traceback()}")
                pass

    async def connect(self):
        return True

    async def listen(self):
        """Listen method of the connector.

        Every connector has to implement the listen method. When an
        infinite loop is running, it becomes hard to cancel this task.
        So we are creating a task and set it on a variable so we can
        cancel the task.

        """
        if self.loop.is_closed():
            self.loop = asyncio.new_event_loop()
        message_getter = self.loop.create_task(await self.get_messages_loop())
        await self._closing.wait()
        message_getter.cancel()

    @register_event(Message)
    async def send_message(self, message):
        """Respond with a message.

        Args:
            message (object): An instance of Message.

        """
        # if self.enable != "True":
        #    return

        # _LOGGER.debug(
        #    _("Responding with: '%s' at target: '%s'"), message.text, message.target
        # )

        # data = dict()
        # data["chat_id"] = message.target
        # data["text"] = message.text

        import base64
        import smtplib
        import ssl
        from email import encoders
        from email.message import EmailMessage
        from email.mime.application import MIMEApplication
        from email.mime.base import MIMEBase
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.utils import formataddr

        # msg = MIMEMultipart('alternative')
        msg = EmailMessage()

        _LOGGER.info("Sending mail...")
        # Establecer la conexión SSL/TLS

        #fromaddr = self.username + "@afip.gob.ar"
        fromaddr = self.username + "@" + self.domain 
        fromname = self.username
        toaddrs = message.target
        tocc = ""
        tocco = ""

        plain = message.text

        # _LOGGER.debug(plain)
        try:
            plain = base64.b64decode(plain)
            plain = plain.decode("utf-8")
        except:
            plain = message.text 
            pass

        txt = plain
        html = plain
        header_html = plain
        msg_body_html = plain
        msg_body_plain = plain

        msg.set_content(plain)
        msg.add_alternative(plain, subtype="text")

        _LOGGER.info(f"000")

        #msg["Subject"] = "ComuBot le ha respondido"
        msg["Subject"] = self.subject
        msg["From"] = formataddr((fromname, fromaddr))
        msg["To"] = toaddrs
        msg["Bcc"] = tocco
        msg["Cc"] = tocc
        #msg.add_header("reply-to", self.username + "@afip.gob.ar")
        msg.add_header("reply-to", self.username + "@" + self.domain)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("AES256-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False

        ctx.load_default_certs()
        try:
            with smtplib.SMTP_SSL(self.smtpserver, self.smtpport, context=ctx) as s:
                destinatarios = toaddrs + "," + tocco + "," + tocc
                destinatarios = destinatarios.split(",")
                destinatarios = [correo for correo in destinatarios if correo]  # elimino direcciones vacias
                _LOGGER.debug(destinatarios)
                s.login(self.username, self.password)
                # s.sendmail(fromaddr, destinatarios, msg)
                s.send_message(msg)
                s.quit()
                _LOGGER.info(
                    "Correo electrónico enviado correctamente.\nTo: "
                    + msg["To"]
                    + "\n"
                    + "Cc: "
                    + msg["Cc"]
                    + "\n"
                    + "Bcc: "
                    + msg["Bcc"]
                )

        except Exception as e:
            _LOGGER.info(f"Error al enviar el correo electrónico: {str(e)}")

        return

    @register_event(Image)
    async def send_image(self, image):
        import base64
        import smtplib
        import ssl
        from email import encoders
        from email.message import EmailMessage
        from email.mime.application import MIMEApplication
        from email.mime.base import MIMEBase
        from email.mime.image import MIMEImage
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.utils import formataddr
        from aiohttp import web


        # msg = MIMEMultipart('alternative')
        # msg = EmailMessage()
        msg = MIMEMultipart()

        _LOGGER.info("Sending mail...")

        #fromaddr = self.username + "@afip.gob.ar"
        fromaddr = self.username + "@" + self.domain
        fromname = self.username
        toaddrs = image.target
        tocc = ""
        tocco = ""

        tipo = image.name
        img = await image.get_file_bytes()
        _LOGGER.info(f"tipo: {tipo}")

        if img != "":
            try:
                html = f"""\
                <html>
                <body>
                """
                #html += """<img src="data:{tipo};base64,{img}">"""  # version de imagen
                html += f"""\
                </body>
                </html>
                """
                part = MIMEText(html, "html")
                msg.attach(part)
                image = MIMEImage(img, name="imagen")
                msg.attach(image)
                _LOGGER.info(f"Image attached")
            except Exception as e:
                _LOGGER.info(f"Error attaching image: {e}")
                return web.Response(status=401, text="Error attaching image.")
                #pass

        #msg["Subject"] = "ComuBot le ha respondido"
        msg["Subject"] = self.subject 
        msg["From"] = formataddr((fromname, fromaddr))
        msg["To"] = toaddrs
        msg["Bcc"] = tocco
        msg["Cc"] = tocc
        msg.add_header("reply-to", self.username + "@" + self.domain )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("AES256-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False

        ctx.load_default_certs()
        try:
            with smtplib.SMTP_SSL(self.smtpserver, self.smtpport, context=ctx) as s:
                destinatarios = toaddrs + "," + tocco + "," + tocc
                destinatarios = destinatarios.split(",")
                destinatarios = [correo for correo in destinatarios if correo]  # elimino direcciones vacias
                _LOGGER.debug(destinatarios)
                s.login(self.username, self.password)
                # s.sendmail(fromaddr, destinatarios, msg)
                _LOGGER.debug(f"{s}")
                # _LOGGER.debug(f"{msg}")
                s.send_message(msg)
                s.quit()
                _LOGGER.info(
                    "Correo electrónico enviado correctamente.\nTo: "
                    + msg["To"]
                    + "\n"
                    + "Cc: "
                    + msg["Cc"]
                    + "\n"
                    + "Bcc: "
                    + msg["Bcc"]
                )

        except Exception as e:
            _LOGGER.error(f"Error al enviar el correo electrónico: {str(e)}")
            _LOGGER.error(f"{traceback.format_exc()}")

        return

    @register_event(File)
    async def send_file(self, file):
        import base64
        import logging
        import smtplib
        import ssl
        from email.mime.application import MIMEApplication
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.utils import formataddr

        _LOGGER.info(file)
        _LOGGER.info("Sending mail...")

        #fromaddr = self.username + "@afip.gob.ar"
        fromaddr = self.username + "@" + self.domain
        fromname = self.username
        toaddrs = file.target
        tocc = ""
        tocco = ""

        msg = MIMEMultipart()
        #msg["Subject"] = "ComuBot le ha respondido"
        msg["Subject"] = self.subject
        msg["From"] = formataddr((fromname, fromaddr))
        msg["To"] = toaddrs
        msg["Bcc"] = tocco
        msg["Cc"] = tocc
        msg.add_header("reply-to", self.username + "@" + self.domain)

        plain_text = "Archivo adjunto."
        msg.attach(MIMEText(plain_text, "plain"))

        #archivo_base64 = await file.get_file_bytes()
        #archivo_bytes = base64.b64decode(archivo_base64)
        #archivo_bytes = file.file_bytes
         
        archivo_bytes = await file.get_file_bytes()
        if archivo_bytes:
            try:
                #tipo_archivo = file.name.split("/")[-1]
                tipo_archivo = file.name
                nombre_archivo = f"{tipo_archivo}" if tipo_archivo else "archivo.pdf"       

                part = MIMEApplication(archivo_bytes, Name=nombre_archivo)
                part["Content-Disposition"] = f'attachment; filename="{nombre_archivo}"'
                part["Content-Type"] = f"{file.name}"
                msg.attach(part)
                _LOGGER.info("File attached")
            except Exception as e:
                _LOGGER.error(f"Error attaching file: {str(e)}")

        ctx = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL(self.smtpserver, self.smtpport, context=ctx) as s:
                destinatarios = [toaddrs] + [to for to in (tocco, tocc) if to]
                _LOGGER.debug(destinatarios)
                s.login(self.username, self.password)
                s.send_message(msg)
                _LOGGER.info(
                    "Correo electrónico enviado correctamente.\nTo: "
                    + msg["To"]
                    + "\n"
                    + "Cc: "
                    + msg["Cc"]
                    + "\n"
                    + "Bcc: "
                    + msg["Bcc"]
                )
        except Exception as e:
            _LOGGER.error(f"Error al enviar el correo electrónico: {str(e)}")

        return
