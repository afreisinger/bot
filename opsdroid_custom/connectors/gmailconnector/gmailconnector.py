"""A connector for Gmail."""

import asyncio
import email
import imaplib
import logging
import traceback

from opsdroid.connector import Connector
from opsdroid.events import Message
from voluptuous import Required

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = {
    Required("username"): str,
    Required("password"): str,
    Required("imapserver"): str,
    Required("imapport"): int,
    Required("telegram_chat_id"): int,
    "update-interval": float,
    "default-user": str,
    "whitelisted-users": list,
    "enable": str,
}


class ConnectorGmail(Connector):
    """Connector to interact with Gmail."""

    def __init__(self, config, opsdroid=None):
        """Initialize Gmail connector."""
        super().__init__(config, opsdroid=opsdroid)
        _LOGGER.info(("Loaded Gmail Connector"))
        self.name = "gmail"
        self.opsdroid = opsdroid
        self.update_interval = config.get("update-interval", 30)
        self.username = config["username"]
        self.password = config["password"]
        self.imapserver = config["imapserver"]
        self.imapport = config["imapport"]
        self.telegram_chat_id = config["telegram_chat_id"]
        # self.whitelisted_users = config["whitelisted_users"]
        self.listening = config.get("listening", "False")
        _LOGGER.info("Initialized Gmail connector.")
        _LOGGER.info(f"Enable:  {self.listening}")
        # _LOGGER.info(f"Whitelisted:  {self.whitelisted_users}")

    async def connect(self):
        import ssl

        """Establece conexión inicial."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.set_ciphers("AES256-SHA")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.check_hostname = False
            ctx.load_default_certs()

            mail = imaplib.IMAP4_SSL(self.imapserver, self.imapport)
            mail.login(self.username, self.password)
            mail.logout()
            _LOGGER.info("Conexión inicial a Gmail exitosa.")
            return True
        except Exception as e:
            _LOGGER.error(f"Error conectando a Gmail: {e}")
            return False

    async def listen(self):
        """Listen for incoming messages."""
        while self.listening:
            await asyncio.sleep(self.update_interval)
            await self._fetch_messages()

    async def _fetch_messages(self):
        """Fetch unread messages using IMAP."""
        try:
            mail = imaplib.IMAP4_SSL(self.imapserver, self.imapport)
            mail.login(self.username, self.password)
            mail.select("inbox")  # Access inbox
            _LOGGER.debug(f"Trying to get messages from {self.imapserver}:{self.imapport}")
            _LOGGER.debug(f"Using  {self.username}")

            status, messages = mail.search(None, "UNSEEN")  # Fetch unseen emails
            if status != "OK":
                _LOGGER.warning("Failed to fetch unseen messages.")
                return

            for num in messages[0].split():
                status, data = mail.fetch(num, "(RFC822)")
                if status != "OK":
                    _LOGGER.warning(f"Failed to fetch email {num}.")
                    continue

                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)

                # Extract email details
                from_email = email_message["From"]
                subject = email_message["Subject"]
                # body = self._get_email_body(email_message)
                sender_email = self._parse_sender_email(from_email)

                _LOGGER.info(f"Received email from {from_email}: Subject {subject}")
                _LOGGER.info(f"Address: {sender_email}")

                # ME PREOCUPO DESPUES POR ESTO

                # if sender_email in self.whitelisted_users:

                #     message = Message(
                #         text=body,
                #         user=from_email,
                #         target=from_email,
                #         connector=self,
                #     )
                #     await self.opsdroid.parse(message)

                # message_text = f"New email from {from_email}: {subject}\n{body}"
                message_text = f"New email from {from_email}: {subject}"
                await self._send_telegram_message(message_text)

                # Mark email as seen
                mail.store(num, "+FLAGS", "\\Seen")
            mail.logout()

        except Exception as e:
            _LOGGER.error(f"Error while fetching messages: {str(e)}")
            _LOGGER.error(traceback.format_exc())

    def _parse_sender_email(self, sender):
        """Extrae el correo electrónico del remitente."""
        if "<" in sender and ">" in sender:
            return sender.split("<")[1].strip(">")
        return sender

    def _get_email_body(self, email_message):
        """Extract the plain text body from an email message."""
        for part in email_message.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode()
        return ""

    async def _send_telegram_message(self, message_text):
        """Send a message to Telegram."""
        # Buscar el conector de Telegram
        telegram_connector = next((c for c in self.opsdroid.connectors if c.name == "telegrampostgmail"), None)
        if not telegram_connector:
            _LOGGER.error("Telegram connector not found!")
            return

        message = Message(
            text=message_text,
            user=self.username,  # Identificador del usuario
            target=self.telegram_chat_id,  # MMMMMMMMMMMMMMMMMMMMMMMM
            connector=telegram_connector,
        )
        await self.opsdroid.parse(message)
        _LOGGER.info(f"Sent Telegram message: {message_text}")

    # @register_event(Message)
    # async def handle_message_event(self, message):
    #     """Handle Message events."""
    #     _LOGGER.info(f"Handler activado: Mensaje recibido: {message.text}")

    #     # Ejemplo de respuesta al evento recibido
    #     response_text = f"Procesé el mensaje: {message.text}"
    #     await self._send_telegram_message(response_text)
