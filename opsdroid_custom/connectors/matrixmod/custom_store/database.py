# Copyright 2018 Zil0
# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import wraps
from typing import List, Optional

from peewee import DoesNotExist, MySQLDatabase
from nio.crypto import (
    DeviceStore,
    GroupSessionStore,
    InboundGroupSession,
    OlmAccount,
    OlmDevice,
    OutgoingKeyRequest,
    Session,
    SessionStore,

)

from . import (

    Accounts,
    DeviceKeys,
    DeviceKeys_v1,
    DeviceTrustState,
    EncryptedRooms,
    ForwardedChains,
    DKeys,
    MegolmInboundSessions,
    OlmSessions,
    OutgoingKeyRequests,
    StoreVersion,
    SyncTokens,
    VerifiedDevices,
    BlacklistedDevices,
    IgnoredDevices,

)


def use_database(fn):
    """
    Ensure that the correct database context is used for the wrapped function.
    """

    @wraps(fn)
    def inner(self, *args, **kwargs):
        with self.database.bind_ctx(self.models):
            return fn(self, *args, **kwargs)

    return inner


def use_database_atomic(fn):
    """
    Ensure that the correct database context is used for the wrapped function.

    This also ensures that the database transaction will be atomic.
    """

    @wraps(fn)
    def inner(self, *args, **kwargs):
        with self.database.bind_ctx(self.models):
            with self.database.atomic():
                return fn(self, *args, **kwargs)

    return inner


@dataclass()
class MysqlStore:
    """Storage class for matrix state."""

    models = [
        Accounts,
        OlmSessions,
        MegolmInboundSessions,
        ForwardedChains,
        DeviceKeys,
        EncryptedRooms,
        OutgoingKeyRequests,
        StoreVersion,
        DKeys,
        SyncTokens,
        VerifiedDevices,
        IgnoredDevices,
        BlacklistedDevices,
    ]
    store_version = 2
    
    user_id: str = field()
    device_id: str = field()
    database_name: str = ""
    store_path: str = ""
    pickle_key: str = ""
    database: MySQLDatabase = field(init=False)
    mysql_user: str = "matrix_bot"
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_db: str = "matrix_bot"
    mysql_pass: str = "abc123"

 
    def _create_database(self):
        
        return MySQLDatabase(database=self.mysql_db, user=self.mysql_user, password=self.mysql_pass,
                             host=self.mysql_host, port=int(self.mysql_port))

    def upgrade_to_v2(self):
        with self.database.bind_ctx([DeviceKeys_v1]):
            self.database.drop_tables(
                [
                    DeviceTrustState,
                    DeviceKeys_v1,
                ],
                safe=True,
            )

        with self.database.bind_ctx(self.models):
            self.database.create_tables([DeviceKeys, DeviceTrustState])
        self._update_version(2)

    def __post_init__(self):
        self.mysql_host = os.getenv("MATRIXMOD_MYSQL_HOST")
        self.mysql_port = int(os.getenv("MATRIXMOD_MYSQL_PORT"))
        self.mysql_db = os.getenv("MATRIXMOD_MYSQL_DB")
        self.mysql_user = os.getenv("MATRIXMOD_MYSQL_USER")
        self.mysql_pass = os.getenv("MATRIXMOD_MYSQL_PASS")
        self.database_name = self.database_name
        self.database_path = os.path.join(self.store_path, self.database_name)
        self.database = self._create_database()
        self.database.connect()
        store_version = self._get_store_version()

        # Update the store if it's an old version here.
        if store_version == 1:
            self.upgrade_to_v2()

        with self.database.bind_ctx(self.models):
            self.database.create_tables(self.models)

    def _get_store_version(self):
        with self.database.bind_ctx([StoreVersion]):
            self.database.create_tables([StoreVersion])
            v, _ = StoreVersion.get_or_create(defaults={"version": self.store_version})
            return v.version

    def _update_version(self, new_version):
        with self.database.bind_ctx([StoreVersion]):
            v, _ = StoreVersion.get_or_create(defaults={"version": new_version})
            v.version = new_version
            v.save()

    @use_database
    def _get_account(self):
        try:
            return Accounts.get(
                Accounts.user_id == self.user_id, Accounts.device_id == self.device_id
            )
        except DoesNotExist:
            return None

    def load_account(self) -> Optional[OlmAccount]:
        """Load the Olm account from the database.

        Returns:
            ``OlmAccount`` object, or ``None`` if it wasn't found for the
                current device_id.

        """
        account = self._get_account()
        logging.debug(f"pickle: {str(account)}")
        if not account:
            return None

        return OlmAccount.from_pickle(account.account, self.pickle_key, account.shared)

    @use_database
    def save_account(self, account):
        """Save the provided Olm account to the database.

        Args:
            account (OlmAccount): The olm account that will be pickled and
                saved in the database.
        """
        Accounts.insert(
            user_id=self.user_id,
            device_id=self.device_id,
            shared=account.shared,
            account=account.pickle(self.pickle_key),
        ).on_conflict_ignore().execute()

        Accounts.update(
            {
                Accounts.account: account.pickle(self.pickle_key),
                Accounts.shared: account.shared,
            }
        ).where(
            (Accounts.user_id == self.user_id) & (Accounts.device_id == self.device_id)
        ).execute()

    @use_database
    def load_sessions(self) -> SessionStore:
        """Load all Olm sessions from the database.

        Returns:
            ``SessionStore`` object, containing all the loaded sessions.

        """
        session_store = SessionStore()

        account = self._get_account()

        if not account:
            return session_store

        for s in account.olm_sessions:
            session = Session.from_pickle(s.session, s.creation_time, self.pickle_key)
            session_store.add(s.sender_key, session)

        return session_store

    @use_database
    def save_session(self, curve_key, session):
        """Save the provided Olm session to the database.

        Args:
            curve_key (str): The curve key that owns the Olm session.
            session (Session): The Olm session that will be pickled and
                saved in the database.
        """
        account = self._get_account()
        assert account

        OlmSessions.replace(
            account=account,
            sender_key=curve_key,
            session=session.pickle(self.pickle_key),
            session_id=session.id,
            creation_time=session.creation_time,
            last_usage_date=session.use_time,
        ).execute()

    @use_database
    def load_inbound_group_sessions(self) -> GroupSessionStore:
        """Load all Olm sessions from the database.

        Returns:
            ``GroupSessionStore`` object, containing all the loaded sessions.

        """
        store = GroupSessionStore()

        account = self._get_account()

        if not account:
            return store

        for s in account.inbound_group_sessions:
            session = InboundGroupSession.from_pickle(
                s.session,
                s.fp_key,
                s.sender_key,
                s.room_id,
                self.pickle_key,
                [chain.sender_key for chain in s.forwarded_chains],
            )
            store.add(session)

        return store

    @use_database
    def save_inbound_group_session(self, session):
        """Save the provided Megolm inbound group session to the database.

        Args:
            session (InboundGroupSession): The session to save.
        """
        account = self._get_account()
        assert account

        MegolmInboundSessions.insert(
            sender_key=session.sender_key,
            account=account,
            fp_key=session.ed25519,
            room_id=session.room_id,
            session=session.pickle(self.pickle_key),
            session_id=session.id,
        ).on_conflict_replace().execute()

        MegolmInboundSessions.update(
            {MegolmInboundSessions.session: session.pickle(self.pickle_key)}
        ).where(MegolmInboundSessions.session_id == session.id).execute()

        # TODO, use replace many here
        for chain in session.forwarding_chain:
            ForwardedChains.replace(sender_key=chain, session=session.id).execute()

    @use_database
    def load_device_keys(self) -> DeviceStore:
        """Load all the device keys from the database.

        Returns DeviceStore containing the OlmDevices with the device keys.
        """
        store = DeviceStore()
        account = self._get_account()

        if not account:
            return store

        for d in account.device_keys:
            store.add(
                OlmDevice(
                    d.user_id,
                    d.device_id,
                    {k.device_key_type: k.device_key for k in d.dkeys},
                    display_name=d.display_name,
                    deleted=d.deleted,
                )
            )

        return store

    @use_database_atomic
    def save_device_keys(self, device_keys):
        """Save the provided device keys to the database.

        Args:
            device_keys (Dict[str, Dict[str, OlmDevice]]): A dictionary
                containing a mapping from a user id to a dictionary containing
                a mapping of a device id to a OlmDevice.
        """
        account = self._get_account()
        assert account
        rows = []

        for user_id, devices_dict in device_keys.items():
            for device_id, device in devices_dict.items():
                rows.append(
                    {
                        "account": account,
                        "user_id": user_id,
                        "device_id": device_id,
                        "display_name": device.display_name,
                        "deleted": device.deleted,
                    }
                )
                
                #DKeys.delete().where((DKeys.device == device_id)).execute()
                #DeviceKeys.delete().where((DeviceKeys.user_id == user_id) & (DeviceKeys.device_id == device_id)).execute()
                #Accounts.delete().where((Accounts.user_id == user_id) & (Accounts.device_id == device_id)).execute()
        if not rows:
            return

        for idx in range(0, len(rows), 100):
            data = rows[idx: idx + 100]
            
            #DeviceKeys.insert_many(data).on_conflict(
            #      conflict_target=[Accounts.account,Accounts.user_id,Accounts.device_id],
            #      preserve=[Accounts.account,Accounts.user_id,Accounts.device_id],
            #      update={}).execute()
            self.database.execute_sql("SET FOREIGN_KEY_CHECKS=0")
            DeviceKeys.insert_many(data).on_conflict_replace(replace=True).execute()
            self.database.execute_sql("SET FOREIGN_KEY_CHECKS=1")

        for user_id, devices_dict in device_keys.items():
            for device_id, device in devices_dict.items():
                d = DeviceKeys.get(
                    (DeviceKeys.account == account)
                    & (DeviceKeys.user_id == user_id)
                    & (DeviceKeys.device_id == device_id)
                )

                d.deleted = device.deleted
                d.save()

                for key_type, key in device.keys.items():
                    DKeys.replace(device_key_type=key_type, device_key=key, device=d).on_conflict_replace().execute()

    @use_database
    def load_encrypted_rooms(self):
        """Load the set of encrypted rooms for this account.

        Returns:
            ``Set`` containing room ids of encrypted rooms.

        """
        account = self._get_account()

        if not account:
            return set()

        return {room.room_id for room in account.encrypted_rooms}

    @use_database
    def load_outgoing_key_requests(self):
        """Load the set of outgoing key requests for this account.

        Returns:
            ``Set`` containing request ids of key requests.

        """
        account = self._get_account()

        if not account:
            return {}

        return {
            request.request_id: OutgoingKeyRequest.from_database(request)
            for request in account.out_key_requests
        }

    @use_database
    def add_outgoing_key_request(self, key_request: OutgoingKeyRequest) -> None:
        """Add an outgoing key request to the store."""
        account = self._get_account()
        assert account

        OutgoingKeyRequests.insert(
            request_id=key_request.request_id,
            session_id=key_request.session_id,
            room_id=key_request.room_id,
            algorithm=key_request.algorithm,
            account=account,
        ).on_conflict_replace().execute()

    @use_database
    def remove_outgoing_key_request(self, key_request: OutgoingKeyRequest) -> None:
        """Remove an active outgoing key request from the store."""
        account = self._get_account()
        assert account

        db_key_request = OutgoingKeyRequests.get_or_none(
            OutgoingKeyRequests.request_id == key_request.request_id,
            OutgoingKeyRequests.account == account,
        )

        if db_key_request:
            db_key_request.delete_instance()

    @use_database_atomic
    def save_encrypted_rooms(self, rooms):
        """Save the set of room ids for this account."""
        account = self._get_account()

        assert account

        data = [(room_id, account) for room_id in rooms]

        for idx in range(0, len(data), 400):
            rows = data[idx: idx + 400]
            EncryptedRooms.insert_many(
                rows, fields=[EncryptedRooms.room_id, EncryptedRooms.account]
            ).on_conflict_replace().execute()

    @use_database
    def save_sync_token(self, token: str) -> None:
        """Save the given token"""
        account = self._get_account()
        assert account

        SyncTokens.replace(account=account, token=token).execute()

    @use_database
    def load_sync_token(self) -> Optional[str]:
        account = self._get_account()

        if not account:
            return None

        token = SyncTokens.get_or_none(
            SyncTokens.account == account.id,
        )
        if token:
            return token.token

        return None

    @use_database
    def delete_encrypted_room(self, room: str) -> None:
        """Delete an encrypted room from the store."""
        db_room = EncryptedRooms.get_or_none(EncryptedRooms.room_id == room)
        if db_room:
            db_room.delete_instance()

    @use_database
    def blacklist_device(self, device: OlmDevice) -> bool:
        """Mark a device as blacklisted.

        Args:
            device (OlmDevice): The device that will be marked as blacklisted

        Returns True if the device was blacklisted, False otherwise, e.g. if
        the device was already blacklisted.

        """
        for key_type in device.keys:
            logging.debug(device)
            logging.debug(str(key_type))
            logging.debug(str(device.keys[key_type]))
            key = device.keys[key_type]
            BlacklistedDevices.insert(
                user_id=device.user_id,
                device_id=device.device_id,
                device_key_type=key_type,
                device_key=key,
            ).on_conflict_replace().execute()
        return True

    @use_database
    def unblacklist_device(self, device: OlmDevice) -> bool:
        """Unmark a device as blacklisted.

        Args:
            device (OlmDevice): The device that will be unmarked as blacklisted

        """
        device = BlacklistedDevices.get_or_none(
            BlacklistedDevices.device_id == device.device_id,
            BlacklistedDevices.user_id == device.user_id

        )
        if device:
            device.delete_instance()
        return True

    @use_database
    def verify_device(self, device: OlmDevice) -> bool:
        """Mark a device as verified.

        Args:
            device (OlmDevice): The device that will be marked as verified

        Returns True if the device was verified, False otherwise, e.g. if the
        device was already verified.

        """

        for key_type in device.keys:
            logging.debug(device)
            logging.debug(str(key_type))
            logging.debug(str(device.keys[key_type]))
            key = device.keys[key_type]
            VerifiedDevices.insert(
                user_id=device.user_id,
                device_id=device.device_id,
                device_key_type=key_type,
                device_key=key,
            ).on_conflict_replace().execute()
        return True

    @use_database
    def is_device_verified(self, device: OlmDevice) -> bool:
        """Check if a device is verified.

        Args:
            device (OlmDevice): The device that will be checked if it's
                verified.
        """
        verifieddevice = VerifiedDevices.get_or_none(
            VerifiedDevices.device_id == device.device_id,
            VerifiedDevices.user_id == device.user_id

        )

        if verifieddevice:
            return True
        else:
            return False

    @use_database
    def is_device_blacklisted(self, device: OlmDevice) -> bool:
        """Check if a device is blacklisted.

        Args:
            device (OlmDevice): The device that will be checked if it's
                blacklisted.
        """
        blacklisteddevice = BlacklistedDevices.get_or_none(
            BlacklistedDevices.device_id == device.device_id,
            BlacklistedDevices.user_id == device.user_id

        )

        if blacklisteddevice:
            return True
        else:
            return False

    @use_database
    def unverify_device(self, device: OlmDevice) -> bool:
        """Unmark a device as verified.

        Args:
            device (OlmDevice): The device that will be unmarked as verified

        Returns True if the device was unverified, False otherwise, e.g. if the
        device wasn't verified.

        """

        db_key_request = VerifiedDevices.get_or_none(
            VerifiedDevices.user_id == device.user_id,
            VerifiedDevices.device_id == device.device_id,

        )

        if db_key_request:
            db_key_request.delete_instance()
        return True

    @use_database
    def ignore_device(self, device: OlmDevice) -> bool:
        """Mark a device as ignored.

        Args:
            device (OlmDevice): The device that will be marked as blacklisted

        Returns True if the device was ignored, False otherwise, e.g. if
        the device was already ignored.
        """
        for key_type in device.keys:
            logging.debug(device)
            logging.debug(str(key_type))
            logging.debug(str(device.keys[key_type]))
            key = device.keys[key_type]
            IgnoredDevices.insert(
                user_id=device.user_id,
                device_id=device.device_id,
                device_key_type=key_type,
                device_key=key,
            ).on_conflict_replace().execute()
        return True

    @use_database
    def unignore_device(self, device: OlmDevice) -> bool:
        """Unmark a device as ignored.

        Args:
            device (OlmDevice): The device that will be marked as blacklisted

        Returns True if the device was unignored, False otherwise, e.g. if the
        device wasn't ignored in the first place.
        """
        raise NotImplementedError

    @use_database
    def ignore_devices(self, devices: List[OlmDevice]) -> None:
        """Mark a list of devices as ignored.

        This is a more efficient way to mark multiple devices as ignored.

        Args:
            devices (list[OlmDevice]): A list of OlmDevices that will be marked
                as ignored.

        """
        for device in devices:
            for key_type in device.keys:
                logging.debug(device)
                logging.debug(str(key_type))
                logging.debug(str(device.keys[key_type]))
                key = device.keys[key_type]
                IgnoredDevices.insert(
                    user_id=device.user_id,
                    device_id=device.device_id,
                    device_key_type=key_type,
                    device_key=key,
                ).on_conflict_replace().execute()
        return None

    @use_database
    def is_device_ignored(self, device: OlmDevice) -> bool:
        """Check if a device is ignored.

        Args:
            device (OlmDevice): The device that will be checked if it's
                ignored.
        """
        ignoreddevice = IgnoredDevices.get_or_none(
            IgnoredDevices.device_id == device.device_id,
            IgnoredDevices.user_id == device.user_id

        )

        if ignoreddevice:
            return True
        else:
            return False
