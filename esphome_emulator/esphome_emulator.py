#!/usr/bin/env python
from __future__ import annotations
from typing import Annotated, Optional
import logging
import signal
import pathlib
import typer
from rich.logging import RichHandler

from itertools import cycle
from google.protobuf.message import Message
from noise.connection import NoiseConnection
import binascii
import os
import struct
import secrets

logging.basicConfig(
    level=logging.CRITICAL,
    format="%(message)s",
    handlers=[RichHandler(show_time=False)],
)
logger = logging.getLogger("esphome_emulator")
logger.setLevel(logging.INFO)
logger.debug("Logging enabled.")

app = typer.Typer(help="ESPHome device in Python.", pretty_exceptions_enable=False)

from . import entities as entities
from . import api_pb2 as api

# from aioesphomeapi import api_pb2 as api
from . import sensors as sensors

import uuid
import socket
from google.protobuf.internal.decoder import _DecodeVarint32  # pyright: ignore
import threading
from zeroconf import ServiceInfo, ServiceListener, Zeroconf
import base64


# TODO: clean this mess up
def get_options(descriptor):
    return {k.name: v for k, v in descriptor.GetOptions().ListFields()}


def read_varint(socket):
    """Read a VarInt from the socket."""

    varint_buff = []
    while True:
        byte = socket.recv(1)
        if len(byte) == 0:
            raise EOFError("Connection closed")
        varint_buff.append(byte)
        if (ord(byte) & 0x80) == 0:
            break
    return _DecodeVarint32(b"".join(varint_buff), 0)[0]


# https://stackoverflow.com/q/68968796
encode = lambda n: n.to_bytes(n.bit_length() // 8 + 1, "little", signed=False)
decode = lambda x: int.from_bytes(x, "little", signed=False)


def encode_message(message, proto=b"\x00"):
    try:
        id = int(get_options(message.DESCRIPTOR).get("id"))  # pyright: ignore
    except ValueError as e:
        logger.error(f"Couldn't get ID from message: {message}")
        raise e
    return (
        proto
        + encode(message.ByteSize())
        + encode(int(id))
        + message.SerializeToString()
    )


def wait_for_indicator(client_socket, indicator=b"\x00"):
    logger.debug(f"Waiting for {indicator} byte...")

    # start = datetime.datetime.now(datetime.timezone.utc)
    while True:
        byte = client_socket.recv(1)
        if byte == indicator:
            return
        elif byte == b"":
            pass
        else:
            logger.debug(f"Received {byte} instead of {indicator}?")
            # raise Exception(f"Received bad indicator byte: {byte}")


def get_id_from_message_name(name):
    descriptor = api.DESCRIPTOR.pool.FindMessageTypeByName(name)
    id = get_options(descriptor).get("id")
    return id


def get_id_to_message_mapping(api) -> dict[int, str]:
    message_names: list[str] = [x for x in api.DESCRIPTOR.message_types_by_name]
    reverse_mapping = {name: get_id_from_message_name(name) for name in message_names}
    return {id: name for name, id in reverse_mapping.items() if id is not None}


def send_states(client_socket, states):
    for response in states:
        encoded_response = encode_message(response)
        logger.debug(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
        client_socket.sendall(encoded_response)
        logger.debug(f"Sent {response.DESCRIPTOR.name}.")


class EspHomeServerThread(threading.Thread):

    def __init__(self, client_socket, api_key):
        self.api_key = api_key
        super(EspHomeServerThread, self).__init__(
            target=self.handle_streams, args=(client_socket,)
        )
        self._stop_event = threading.Event()
        self.entities = []

    def stop(self):
        """Thread class with a stop() method. The thread itself has to check
        regularly for the stopped() condition."""
        logger.info("Stop request received.")
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self) -> None:
        return super().run()

    def add_entities(self, entities) -> None:
        logger.info(f"Potential entities to add: {[x.name for x in entities]}")
        [self.entities.append(x) for x in entities if x.list_callback() is not None]

    def read_varint(self, socket):
        """Read a VarInt from the socket."""

        varint_buff = []
        while True:
            byte = socket.recv(1)
            if len(byte) == 0:
                raise EOFError("Connection closed")
            varint_buff.append(byte)
            if (ord(byte) & 0x80) == 0:
                break
        return _DecodeVarint32(b"".join(varint_buff), 0)[0]

    def read_varint_from_bytes(self, data):
        varint_buff = []
        for _, byte in enumerate(data):
            varint_buff.append(byte)
            if (byte & 0x80) == 0:
                break
        return _DecodeVarint32(bytes(varint_buff), 0)[0], len(varint_buff)

    def parse_decrypted_frame(
        self, data, message_map: dict[int, str]
    ) -> tuple[bytes, str, int] | None:
        type_high, type_low, length_high, length_low = struct.unpack(
            "!B B B B", data[0:4]
        )
        message_type = (type_high << 8) | type_low
        message_size = (length_high << 8) | length_low

        message_data = data[4:]

        # https://github.com/esphome/esphome/blob/dev/esphome/components/api/api.proto
        message_type_name = message_map.get(message_type)

        logger.debug(
            f"Received message: {message_type_name} (type: {message_type}, size: {message_size})."
        )

        if message_type_name is None:
            logger.error("Couldn't determine message type from message.")
            return

        return message_data, message_type_name, message_type

    def handle_streams(self, client_socket):
        self.handle_unencrypted_stream(client_socket)
        self.handle_encrypted_stream(client_socket)

    def handle_unencrypted_stream(self, client_socket: socket.socket):

        message_map = get_id_to_message_mapping(api)

        while True:
            wait_for_indicator(client_socket)
            # Read the VarInt denoting the size of the message object
            message_size = read_varint(client_socket)

            # Read the VarInt denoting the type of message
            message_type = read_varint(client_socket)
            message_type_name = message_map.get(message_type)

            # Read the message object encoded as a ProtoBuf message
            data = client_socket.recv(message_size)

            logger.debug(
                f"Received message: {message_type_name} (type: {message_type}, size: {message_size})."
            )

            # return self.handle_encrypted_stream(client_socket, noise)
            self.handle_message(data, message_type_name, message_type)

            return

    def handle_encrypted_stream(
        self,
        client_socket: socket.socket,
    ):
        """Handles a connection from a client and responds to requests."""

        message_map = get_id_to_message_mapping(api)

        key_base64 = self.api_key
        PSK = binascii.a2b_base64(key_base64)
        noise = NoiseConnection.from_name(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        noise.set_as_responder()
        noise.set_psks(psk=PSK)

        while True:
            logger.debug("Trying to handshake...")

            hostname = socket.gethostname()

            data = b"\x01" + str.encode(hostname) + b"\x00"
            header = struct.pack("!B H", 0x01, len(data))
            msg = header + data
            logger.debug(f"Sending: {msg}")
            client_socket.sendall(msg)

            noise.set_prologue(b"NoiseAPIInit\x00\x00")
            noise.start_handshake()

            if noise.noise_protocol is not None:
                logger.debug(f"protocol: {noise.noise_protocol.name}")
                logger.debug(f"keypairs: {noise.noise_protocol.keypairs}")

            message_size = None
            message_type = None
            message_type_name = None

            indicator = client_socket.recv(1)
            if indicator != b"\x00":
                raise Exception(f"Bad indicator: {indicator}")

            message_size = read_varint(client_socket)
            message_type = read_varint(client_socket)
            message_type_name = message_map.get(message_type)

            logger.debug(
                f"Received message: {message_type_name} (type: {message_type}, size: {message_size})."
            )

            # Perform handshake. Break when finished
            for action in cycle(["receive", "send"]):
                if noise.handshake_finished:
                    break
                elif action == "send":
                    logger.debug("Sending encrypted response...")

                    type_: int = 1
                    data = b"\x00"
                    data_len = len(data)
                    data_header = bytes(
                        (
                            (type_ >> 8) & 0xFF,
                            type_ & 0xFF,
                            (data_len >> 8) & 0xFF,
                            data_len & 0xFF,
                        )
                    )
                    frame = b"\x00" + noise.write_message(data_header + data)
                    frame_len = len(frame)
                    header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
                    msg = b"".join([header, frame])

                    logger.debug(f"Sending msg: {msg}")
                    client_socket.sendall(msg)
                    logger.debug("Encrypted respnose sent.")
                    pass
                elif action == "receive":
                    data = client_socket.recv(message_size)
                    plaintext = noise.read_message(data)
                    logger.debug("Decrypted handshake data: %s", plaintext)
            logger.debug("Handshake complete.")

            logger.info("Setup complete, entering request/response loop.")
            while True:
                if self.stopped():
                    logger.info("Got stop signal, disconnecting and exiting thread.")
                    request_disconnect(client_socket)
                    return

                wait_for_indicator(client_socket, indicator=b"\x01")
                header = client_socket.recv(2)
                if len(header) < 2:
                    raise ValueError("Incomplete header received...")
                high_byte, low_byte = struct.unpack("!B B", header)
                frame_len = (high_byte << 8) | low_byte

                data = client_socket.recv(frame_len)

                decrypted_data = noise.decrypt(data)
                unpacked = self.parse_decrypted_frame(decrypted_data, message_map)

                if unpacked is None:
                    logger.warning("Failed to unpack frame, exiting.")
                    return

                message_data, message_type_name, message_type = unpacked
                responses = [
                    x
                    for x in self.handle_message(
                        message_data, message_type_name, message_type
                    )
                    if x is not None
                ]

                for response in responses:
                    logger.debug(
                        f"Sending {response.DESCRIPTOR.name} response: {response}".replace(
                            "\n", " "
                        )
                    )
                    data = response.SerializeToString()
                    logger.debug(f"Serialised response: {data}")

                    type_: int = [
                        k
                        for k, v in message_map.items()
                        if v == response.DESCRIPTOR.name
                    ][0]
                    logger.debug(f"Type of {response.DESCRIPTOR.name} is {type_}")
                    data_len = len(data)
                    logger.debug(
                        f"Data length of {response.DESCRIPTOR.name} is {data_len}"
                    )
                    data_header = bytes(
                        (
                            (type_ >> 8) & 0xFF,
                            type_ & 0xFF,
                            (data_len >> 8) & 0xFF,
                            data_len & 0xFF,
                        )
                    )
                    frame = noise.encrypt(data_header + data)
                    frame_len = len(frame)
                    logger.debug(
                        f"Frame length of {response.DESCRIPTOR.name} is {data_len}"
                    )
                    header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
                    msg = b"".join([header, frame])
                    client_socket.sendall(msg)
                    logger.debug(f"Full message for {response.DESCRIPTOR.name}: {msg}")
                    logger.debug(f"Sent {response.DESCRIPTOR.name}.")

                    if "DisconnectResponse" in [x.DESCRIPTOR.name for x in responses]:
                        logger.info("Sent a DisconnectResponse, disconnecting now.")
                        return

    def handle_message(
        self,
        data,
        message_type_name,
        message_type,
    ) -> list[Message]:
        """Handles a mesage and returns messages to send back."""

        if message_type_name == "HelloRequest":
            request = api.HelloRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.HelloResponse()
            response.server_info = "esphome_emulator"
            response.name = socket.gethostname()
            return [response]

        elif message_type_name == "ConnectRequest":
            request = api.ConnectRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.ConnectResponse()
            response.invalid_password = False
            return [response]
        elif message_type_name == "DisconnectRequest":
            request = api.DisconnectRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            logger.info("Received DisconnectRequest, sending response...")
            response = api.DisconnectResponse()
            return [response]
        elif message_type_name == "PingRequest":
            request = api.PingRequest()
            request.ParseFromString(data)

            response = api.PingResponse()

            states = [
                x.state_callback()
                for x in self.entities
                if x.state_callback is not None
            ]
            logger.debug(f"Returning {len(states)} states...")
            return [response, *states]
        elif message_type_name == "DeviceInfoRequest":
            request = api.DeviceInfoRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.DeviceInfoResponse()
            response.uses_password = False
            # https://stackoverflow.com/questions/159137/getting-mac-address#comment42261244_159195
            response.mac_address = ":".join(
                ("%012X" % uuid.getnode())[i : i + 2] for i in range(0, 12, 2)
            )
            response.model = "host"
            response.manufacturer = "Python"
            response.friendly_name = socket.gethostname()
            return [response]
        elif message_type_name == "ListEntitiesRequest":
            request = api.ListEntitiesRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            list_responses = [x.list_callback() for x in self.entities]

            response = api.ListEntitiesDoneResponse()
            return [*list_responses, response]
        elif message_type_name == "SubscribeLogsRequest":
            request = api.SubscribeLogsRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            response = api.SubscribeLogsResponse()
            response.level = api.LogLevel.LOG_LEVEL_INFO
            response.message = "Connected to ESPHome dashboard..."
            return [response]
        elif message_type_name == "SubscribeStatesRequest":
            request = api.SubscribeStatesRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            states = [
                x.state_callback()
                for x in self.entities
                if x.state_callback is not None
            ]
            return states
        elif message_type_name == "SubscribeHomeassistantServicesRequest":
            request = api.SubscribeHomeassistantServicesRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            return []
            # Note: empty `service` field causes an exception in HA and hangs the connection
            # response = api.HomeassistantServiceResponse()
            # encoded_response = encode_message(response)
            # logger.debug(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            # client_socket.sendall(encoded_response)
            # logger.debug(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "SubscribeHomeAssistantStatesRequest":
            request = api.SubscribeHomeAssistantStatesRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            return []
        elif message_type_name == "HomeAssistantStateResponse":
            request = api.HomeAssistantStateResponse()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            return []
        elif message_type_name == "MediaPlayerCommandRequest":
            request = api.MediaPlayerCommandRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            states = [
                x.command_callback(request)
                for x in self.entities
                if x.entity_type == "MediaPlayerEntity" and x.key == request.key
            ]
            return states
        elif message_type_name == "SelectCommandRequest":
            request = api.SelectCommandRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            states = [
                x.command_callback(request)
                for x in self.entities
                if x.entity_type == "SelectEntity" and x.key == request.key
            ]
            logger.debug(
                f"Sending states {[x for x in states]} after SelectCommandRequest..."
            )
            return states
        elif message_type_name == "LightCommandRequest":
            request = api.LightCommandRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            states = [
                x.command_callback(request)
                for x in self.entities
                if x.entity_type == "LightEntity" and x.key == request.key
            ]
            logger.debug(
                f"Sending states {[x for x in states]} after LightCommandRequest..."
            )
            return states
        elif message_type_name == "ButtonCommandRequest":
            request = api.ButtonCommandRequest()
            request.ParseFromString(data)
            logger.debug(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            states = [
                x.command_callback(request)
                for x in self.entities
                if x.entity_type == "ButtonEntity" and x.key == request.key
            ]
            logger.debug(f"Sending states {[x for x in states]}...")
            return states
        else:
            raise Exception(
                f"Unhandled message type: {message_type_name} (id: {message_type})."
            )


def request_disconnect(client_socket):
    request = api.DisconnectRequest()
    encoded_request = encode_message(request)
    logger.info(f"Sending {request.DESCRIPTOR.name}: {encoded_request}...")
    client_socket.sendall(encoded_request)
    logger.info(f"Sent {request.DESCRIPTOR.name}, disconnecting.")


class EspHomeListener(ServiceListener):
    def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        logger.debug(f"{zc} Service {name} of type {type_} updated.")

    def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        logger.debug(f"{zc} Service {name} of type {type_} removed.")

    def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        logger.debug(f"{zc} Service {name} of type {type_} added.")


def has_ip_address():
    """Return True if any non-loopback interface has an IPv4 address."""
    try:
        # Get a list of all interfaces except loopback
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            if iface == 'lo':
                continue  # skip loopback
            try:
                # Try to get IP address for this interface
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(
                    socket.inet_aton(socket.gethostbyname(socket.gethostname()))
                )
                # This is a bit hacky — better check per interface:
                import fcntl
                import struct
                ip = fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', iface[:15].encode('utf-8'))
                )[20:24]
                ip_str = socket.inet_ntoa(ip)
                if ip_str and not ip_str.startswith("127."):
                    return True
            except OSError:
                pass
    except FileNotFoundError:
        pass
    return False

def wait_for_ip_address():
    logger.info("Waiting for network interface with IP address...")
    while not has_ip_address():
        time.sleep(1)

    logger.info("IP address acquired!")

class EsphomeServer(object):
    esphome_server_threads: list[EspHomeServerThread] = []
    client_sockets: list[socket.socket] = []

    def __init__(self, api_key) -> None:
        self.api_key = api_key
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def run(self):
        """Run the ESPHome-like server."""

        logger.info("Starting esphome_emulator...")

        wait_for_ip_address()

        address = ("0.0.0.0", 6053)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(address)
        server_socket.listen(5)

        logger.info("Listening...")
        properties = {
            "friendly_name": socket.gethostname(),
            # "version=2024.5.4",
            "mac": hex(uuid.getnode()).split("x")[1],
            "platform": "Host",
            # "board=Host",
            # "network=wifi",
            "api_encryption": b"Noise_NNpsk0_25519_ChaChaPoly_SHA256",
        }

        zeroconf = Zeroconf()
        zeroconf.add_service_listener(
            type_="_esphomelib._tcp.local.", listener=EspHomeListener()
        )
        service_info = ServiceInfo(
            type_="_esphomelib._tcp.local.",
            name=f"{socket.gethostname()}._esphomelib._tcp.local.",
            port=6053,
            properties=properties,
            server=f"{socket.gethostname()}.local.",
        )
        zeroconf.update_service(service_info)
        logger.debug("Finished setting up zerconf.")

        try:
            while True:
                client_socket = None
                addr = None
                client_socket, addr = server_socket.accept()
                self.client_sockets.append(client_socket)
                connection_from = ":".join([str(x) for x in addr])
                logger.info(f"Connection from {connection_from}...")
                esphome_server_thread = EspHomeServerThread(client_socket, self.api_key)
                entities = [
                    # sensors.DeadbeefEntity(esphome_server_thread),
                    # sensors.NowPlayingEntity(esphome_server_thread),
                    sensors.MprisMediaPlayerEntity(esphome_server_thread),
                    sensors.MprisNowPlayingEntity(esphome_server_thread),
                    sensors.MprisIsMovie(esphome_server_thread),
                    sensors.AudioOutputEntity(esphome_server_thread),
                    sensors.MonitorBacklightEntity(esphome_server_thread),
                    sensors.SuspendButtonEntity(esphome_server_thread),
                    sensors.PowerOffButtonEntity(esphome_server_thread),
                    sensors.RestartButtonEntity(esphome_server_thread),
                    sensors.GamingStatusEntity(esphome_server_thread),
                    sensors.GamemodeTextSensorEntity(esphome_server_thread),
                    sensors.MonitorSelectEntity(esphome_server_thread),
                    # sensors.TextSensorTest(esphome_server_thread),
                    sensors.StatusEntity(esphome_server_thread),
                    sensors.SuspendDisplayButtonEntity(esphome_server_thread),
                ]
                esphome_server_thread.add_entities(entities=entities)

                threads_started_for = ":".join([str(x) for x in addr])
                logger.info(f"Starting thread for {threads_started_for}...")
                # esphome_server_thread.handle_streams(client_socket)
                esphome_server_thread.start()
                self.esphome_server_threads.append(esphome_server_thread)
                # except EOFError:
                #     logger.error(f"Client with address \"{addr}\" disconnected...")
                #     pass
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            self.exit_gracefully()
        except Exception:
            logger.exception("Got an unexpected error...")
        finally:
            logger.info("Shutting down...")
            self.exit_gracefully()

    def exit_gracefully(self, *args, **kwargs):
        logger.info(f"Got exit request with args {args} and kwargs {kwargs}")
        logger.info(
            f"Waiting for {len(self.esphome_server_threads)} threads to stop..."
        )
        [x.stop() for x in self.esphome_server_threads]
        [x.join() for x in self.esphome_server_threads]
        self.esphome_server_threads = []
        logger.info("All threads stopped.")
        for client_socket in self.client_sockets:
            logger.info(f"Closing socket...")
            try:
                client_socket.close()
            except Exception as e:
                logger.warning(f"Got exception while trying to close socket: {e}")
                pass
            logger.info(f"Socket closed.")
        self.client_sockets = []
        logger.info(f"Exiting.")
        exit(0)
    

@app.command()
def run(
    api_key: str = typer.Option(envvar="ESPHOME_EMULATOR_API_KEY"),
    debug: bool = typer.Option(envvar="ESPHOME_EMULATOR_DEBUG", default=False),
):
    """Run the esphome_emulator server."""

    if debug:
        logger.setLevel(logging.DEBUG)

    esphome_server = EsphomeServer(api_key)
    esphome_server.run()

@app.command()
def install(
    force: bool = typer.Option(
        help="Overwrite unit files if they exist.", default=False
    )
):
    """Install and configure the unit file"""

    logger.info("Installing unit file...")
    unit_path = os.path.expanduser("~/.config/systemd/user/esphome_emulator.service")
    unit_fragment_path = os.path.expanduser(
        "~/.config/systemd/user/esphome_emulator.service.d/override.conf"
    )
    if not force:
        if os.path.exists(unit_path):
            logger.warning("File already exists at %s, doing nothing.", unit_path)
            return
        if os.path.exists(unit_fragment_path):
            logger.warning(
                "File already exists at %s, doing nothing.", unit_fragment_path
            )
            return
    key = secrets.token_bytes(32)
    base64_key = base64.b64encode(key).decode()
    bin_path = os.path.expanduser("~/.local/bin/esphome_emulator")
    unit = f"""[Unit]
Description=Esphome Emulator
After=networking.target

[Service]
Type=simple
Restart=on-failure
ExecStart={bin_path} run
Environment="ESPHOME_EMULATOR_API_KEY={base64_key}"

[Install]
WantedBy=default.target
"""
    logger.info("Installing unit file at %s...", unit_path)
    pathlib.Path(os.path.dirname(unit_path)).mkdir(parents=True, exist_ok=True)
    with open(file=unit_path, mode="w") as fh:
        fh.write(unit)

    unit_fragment = f"""[Service]
Environment="ESPHOME_EMULATOR_API_KEY={base64_key}"
"""
    logger.info("Installing API key at %s...", unit_fragment_path)
    pathlib.Path(os.path.dirname(unit_fragment_path)).mkdir(parents=True, exist_ok=True)
    with open(file=unit_fragment_path, mode="w") as fh:
        fh.write(unit_fragment)
    logger.info("Your API key for Home Assistant is: %s", base64_key)

    logger.info(
        "Finished installation, please run: systemctl daemon-reload --user && systemctl enable --user --now esphome_emulator"
    )
