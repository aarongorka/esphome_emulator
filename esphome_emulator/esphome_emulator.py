#!/usr/bin/env python
from typing import Callable

from google.protobuf.descriptor import Descriptor
from google.protobuf.service import RpcChannel
from . import api_pb2 as api
import uuid
import time
import socket
from google.protobuf.internal.decoder import _DecodeVarint32 # pyright: ignore
import datetime
import threading
from zeroconf import ServiceInfo, ServiceListener, Zeroconf

# print(f"list[{'|'.join([f"api.{v.DESCRIPTOR.name}" for k, v in api.__dict__.items() if k.startswith("List")])}]")
# print(f"list[{'|'.join([f"api.{v.DESCRIPTOR.name}" for k, v in api.__dict__.items() if k.endswith("StateResponse")])}]")

type GetListsResponse = list[api.ListEntitiesRequest | api.ListEntitiesDoneResponse | api.ListEntitiesBinarySensorResponse | api.ListEntitiesCoverResponse | api.ListEntitiesFanResponse | api.ListEntitiesLightResponse | api.ListEntitiesSensorResponse | api.ListEntitiesSwitchResponse | api.ListEntitiesTextSensorResponse | api.ListEntitiesServicesArgument | api.ListEntitiesServicesResponse | api.ListEntitiesCameraResponse | api.ListEntitiesClimateResponse | api.ListEntitiesNumberResponse | api.ListEntitiesSelectResponse | api.ListEntitiesLockResponse | api.ListEntitiesButtonResponse | api.ListEntitiesMediaPlayerResponse | api.ListEntitiesAlarmControlPanelResponse | api.ListEntitiesTextResponse | api.ListEntitiesDateResponse | api.ListEntitiesTimeResponse | api.ListEntitiesEventResponse | api.ListEntitiesValveResponse | api.ListEntitiesDateTimeResponse | api.ListEntitiesUpdateResponse]

type GetStatesResponse = list[api.BinarySensorStateResponse | api.CoverStateResponse | api.FanStateResponse | api.LightStateResponse | api.SensorStateResponse | api.SwitchStateResponse | api.TextSensorStateResponse | api.SubscribeHomeAssistantStateResponse | api.HomeAssistantStateResponse | api.ClimateStateResponse | api.NumberStateResponse | api.SelectStateResponse | api.LockStateResponse | api.MediaPlayerStateResponse | api.AlarmControlPanelStateResponse | api.TextStateResponse | api.DateStateResponse | api.TimeStateResponse | api.ValveStateResponse | api.DateTimeStateResponse | api.UpdateStateResponse]

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
    return _DecodeVarint32(b''.join(varint_buff), 0)[0]

# https://stackoverflow.com/q/68968796
encode = lambda n: n.to_bytes(n.bit_length()//8 + 1, 'little', signed=False)
decode = lambda x: int.from_bytes(x, 'little', signed=False)

def encode_message(message):
    try:
        id = int(get_options(message.DESCRIPTOR).get("id")) # pyright: ignore
    except ValueError as e:
        print(f"Couldn't get ID from message: {message}")
        raise e
    return b'\x00' + encode(message.ByteSize()) + encode(int(id)) + message.SerializeToString()

def wait_for_zero(client_socket):
    print("Waiting for zero byte...")

    start = datetime.datetime.now(datetime.timezone.utc)
    while client_socket.recv(1) != b'\x00':
        now = datetime.datetime.now(datetime.timezone.utc)
        if now - start < datetime.timedelta(seconds=60):
            time.sleep(1)
        elif now - start < datetime.timedelta(seconds=80):
            print("Haven't heard from ESPHome for a while...")
            request = api.PingRequest()
            encoded_request = encode_message(request)
            print(f"Sending {request.DESCRIPTOR.name}: {encoded_request}...")
            client_socket.sendall(encoded_request)
            print(f"Sent {request.DESCRIPTOR.name}.")
            return
        else:
            print("Waiting for too long, disconnecting.")
            request_disconnect(client_socket)
            client_socket.close()

def get_id_from_message_name(name):
    descriptor = api.DESCRIPTOR.pool.FindMessageTypeByName(name)
    id = get_options(descriptor).get("id")
    return id

def get_id_to_message_mapping(api):
    message_names: list[str] = [x for x in api.DESCRIPTOR.message_types_by_name]
    reverse_mapping = {name: get_id_from_message_name(name) for name in message_names}
    return {id: name for name, id in reverse_mapping.items() if id is not None}

def send_states(client_socket, states):
    for response in states:
        encoded_response = encode_message(response)
        print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
        client_socket.sendall(encoded_response)
        print(f"Sent {response.DESCRIPTOR.name}.")

def handle_client(
    client_socket,
    message_map: dict[int, str],
    get_lists: Callable[[], GetListsResponse],
    get_states: Callable[[], GetStatesResponse],
    handle_media_command: Callable[[api.MediaPlayerCommandRequest], GetStatesResponse]
):
    """Handles a connection from a client and responds to requests."""

    while True:
        wait_for_zero(client_socket)

        # Read the VarInt denoting the size of the message object
        message_size = read_varint(client_socket)

        # Read the VarInt denoting the type of message
        message_type = read_varint(client_socket)
        message_type_name = message_map.get(message_type)

        # Read the message object encoded as a ProtoBuf message
        data = client_socket.recv(message_size)

        print(f"Received message: {message_type_name} (type: {message_type}, size: {message_size}).")
        # https://github.com/esphome/esphome/blob/dev/esphome/components/api/api.proto

        if message_type_name == "HelloRequest":
            request = api.HelloRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.HelloResponse()
            response.server_info = "esphome_emulator"
            response.name = socket.gethostname()

            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
            print(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "ConnectRequest":
            request = api.ConnectRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.ConnectResponse()
            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
        elif message_type_name == "DisconnectRequest":
            request = api.DisconnectRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.DisconnectResponse()
            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
            print(f"Sent {response.DESCRIPTOR.name}, disconnecting.")
            client_socket.close()
        elif message_type_name == "PingRequest":
            request = api.PingRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.PingResponse()
            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)

            states = get_states()
            send_states(client_socket, states)
        elif message_type_name == "DeviceInfoRequest":
            request = api.DeviceInfoRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            response = api.DeviceInfoResponse()
            response.uses_password = False
            # https://stackoverflow.com/questions/159137/getting-mac-address#comment42261244_159195
            response.mac_address =':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
            response.model = "host"
            response.manufacturer = "Python"
            response.friendly_name = socket.gethostname()

            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
            print(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "ListEntitiesRequest":
            request = api.ListEntitiesRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            lists = get_lists()
            for response in lists:
                encoded_response = encode_message(response)
                print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
                client_socket.sendall(encoded_response)
                print(f"Sent {response.DESCRIPTOR.name}.")
                encoded_response = None

            response = api.ListEntitiesDoneResponse()
            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
            print(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "SubscribeLogsRequest":
            request = api.SubscribeLogsRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            response = api.SubscribeLogsResponse()
            response.level = api.LogLevel.LOG_LEVEL_INFO
            response.message = "Connected to ESPHome dashboard..."
            encoded_response = encode_message(response)
            print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            client_socket.sendall(encoded_response)
            print(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "SubscribeStatesRequest":
            request = api.SubscribeStatesRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            states = get_states()
            send_states(client_socket, states)
        elif message_type_name == "SubscribeHomeassistantServicesRequest":
            request = api.SubscribeHomeassistantServicesRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")

            # Note: empty `service` field causes an exception in HA and hangs the connection
            # response = api.HomeassistantServiceResponse()
            # encoded_response = encode_message(response)
            # print(f"Sending {response.DESCRIPTOR.name}: {encoded_response}...")
            # client_socket.sendall(encoded_response)
            # print(f"Sent {response.DESCRIPTOR.name}.")
        elif message_type_name == "SubscribeHomeAssistantStatesRequest":
            request = api.SubscribeHomeAssistantStatesRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
        elif message_type_name == "HomeAssistantStateResponse":
            request = api.HomeAssistantStateResponse()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
        elif message_type_name == "MediaPlayerCommandRequest":
            request = api.MediaPlayerCommandRequest()
            request.ParseFromString(data)
            print(f"Parsed {request.DESCRIPTOR.name}: {str(request).strip()}")
            states = handle_media_command(request)
            send_states(client_socket, states)
        else:
            raise Exception(f"Unhandled message type: {message_type_name} (id: {message_type}).")

def request_disconnect(client_socket):
    request = api.DisconnectRequest()
    encoded_request = encode_message(request)
    print(f"Sending {request.DESCRIPTOR.name}: {encoded_request}...")
    client_socket.sendall(encoded_request)
    print(f"Sent {request.DESCRIPTOR.name}, disconnecting.")
    client_socket.close()

class EspHomeListener(ServiceListener):
    def update_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        print(f"Service {name} updated.")

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        print(f"Service {name} removed.")

    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        print(f"Service {name} added.")

def run(
    get_lists: Callable[[], GetListsResponse],
    get_states: Callable[[], GetStatesResponse],
    handle_media_command: Callable[[api.MediaPlayerCommandRequest], list[api.MediaPlayerStateResponse]],
):
    """Run the ESPHome-like server."""

    message_map = get_id_to_message_mapping(api)

    address = ('0.0.0.0', 6053)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(address)
    server_socket.listen(5)


    print("Listening...")
    properties = {
        "friendly_name": socket.gethostname(),
        # "version=2024.5.4",
        "mac": hex(uuid.getnode()).split("x")[1],
        "platform": "Host",
        # "board=Host",
        # "network=wifi",
        # "api_encryption=Noise_NNpsk0_25519_ChaChaPoly_SHA256",
    }

    zeroconf = Zeroconf()
    zeroconf.add_service_listener(type_="_esphomelib._tcp.local.", listener=EspHomeListener())
    service_info = ServiceInfo(
        type_="_esphomelib._tcp.local.",
        name=f"{socket.gethostname()}.local.",
        port=6053,
        properties=properties,
        server=f"{socket.gethostname()}.local."
    )
    zeroconf.update_service(service_info)

    client_socket = None
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}...")
            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    client_socket,
                    message_map,
                    get_lists,
                    get_states,
                    handle_media_command,
                )
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down...")
    except EOFError:
        print("Client disconnected, shutting down...")
    finally:
        if client_socket is not None:
            try:
                request_disconnect(client_socket)
                client_socket.close()
            except BrokenPipeError:
                pass
