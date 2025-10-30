#!/usr/bin/env python
from __future__ import annotations
from typing import Callable
from . import api_pb2 as api

# from aioesphomeapi import api_pb2 as api
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("esphome_emulator")

ListEntitiesResponses = (
    api.ListEntitiesAlarmControlPanelResponse
    | api.ListEntitiesBinarySensorResponse
    | api.ListEntitiesButtonResponse
    | api.ListEntitiesCameraResponse
    | api.ListEntitiesClimateResponse
    | api.ListEntitiesCoverResponse
    | api.ListEntitiesDateResponse
    | api.ListEntitiesDateTimeResponse
    | api.ListEntitiesDoneResponse
    | api.ListEntitiesEventResponse
    | api.ListEntitiesFanResponse
    | api.ListEntitiesLightResponse
    | api.ListEntitiesLockResponse
    | api.ListEntitiesMediaPlayerResponse
    | api.ListEntitiesNumberResponse
    | api.ListEntitiesRequest
    | api.ListEntitiesSelectResponse
    | api.ListEntitiesSensorResponse
    | api.ListEntitiesServicesArgument
    | api.ListEntitiesServicesResponse
    | api.ListEntitiesSwitchResponse
    | api.ListEntitiesTextResponse
    | api.ListEntitiesTextSensorResponse
    | api.ListEntitiesTimeResponse
    | api.ListEntitiesUpdateResponse
    | api.ListEntitiesValveResponse
)


StateResponses = (
    api.AlarmControlPanelStateResponse
    | api.BinarySensorStateResponse
    | api.ClimateStateResponse
    | api.CoverStateResponse
    | api.DateStateResponse
    | api.DateTimeStateResponse
    | api.FanStateResponse
    | api.HomeAssistantStateResponse
    | api.LightStateResponse
    | api.LockStateResponse
    | api.MediaPlayerStateResponse
    | api.NumberStateResponse
    | api.SelectStateResponse
    | api.SensorStateResponse
    | api.SubscribeHomeAssistantStateResponse
    | api.SwitchStateResponse
    | api.TextSensorStateResponse
    | api.TextStateResponse
    | api.TimeStateResponse
    | api.UpdateStateResponse
    | api.ValveStateResponse
)


CommandRequests = (
    api.AlarmControlPanelCommandRequest
    | api.ButtonCommandRequest
    | api.ClimateCommandRequest
    | api.CoverCommandRequest
    | api.DateCommandRequest
    | api.DateTimeCommandRequest
    | api.FanCommandRequest
    | api.LightCommandRequest
    | api.LockCommandRequest
    | api.MediaPlayerCommandRequest
    | api.NumberCommandRequest
    | api.SelectCommandRequest
    | api.SwitchCommandRequest
    | api.TextCommandRequest
    | api.TimeCommandRequest
    | api.UpdateCommandRequest
    | api.ValveCommandRequest
)


class BaseEntity(ABC):
    def __init__(
        self,
        esphome,
        list_callback: Callable[
            [],
            ListEntitiesResponses | None,
        ],
        state_callback: (
            Callable[
                [],
                StateResponses | None,
            ]
            | None
        ),
        command_callback: (
            Callable[
                [CommandRequests],
                StateResponses | None,
            ]
            | None
        ),
    ):
        self.name = type(self).__name__
        self.list_callback = list_callback
        self.state_callback = state_callback
        self.command_callback = command_callback
        self.key = self.get_key(esphome)

    def get_key(self, esphome) -> int:
        try:
            key = self.key
        except AttributeError:
            key = int(
                str(abs(int(hash(self.name))))[:5]
            )  # TODO: real method of generating a unique key
            logger.info(f"Setting {self.name} key to {key}...")
        return key

    # @abstractmethod
    # def list_callback(self):
    #     pass
    #
    # @abstractmethod
    # def state_callback(self):
    #     pass
    #
    # @abstractmethod
    # def command_callback(self):
    #     pass


class MediaPlayerEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesMediaPlayerResponse | None],
        state_callback: Callable[[], api.MediaPlayerStateResponse | None],
        command_callback: Callable[
            [api.MediaPlayerCommandRequest], api.MediaPlayerStateResponse | None
        ],
    ):
        self.entity_type = "MediaPlayerEntity"
        # TODO: figure out why pyright is complaining about this
        super().__init__(esphome, list_callback, state_callback, command_callback)


class SelectEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesSelectResponse | None],
        state_callback: Callable[[], api.SelectStateResponse | None],
        command_callback: Callable[
            [api.SelectCommandRequest], api.SelectStateResponse | None
        ],
    ):
        self.entity_type = "SelectEntity"
        super().__init__(esphome, list_callback, state_callback, command_callback)


class LightEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesLightResponse | None],
        state_callback: Callable[[], api.LightStateResponse | None],
        command_callback: Callable[
            [api.LightCommandRequest], api.LightStateResponse | None
        ],
    ):
        self.entity_type = "LightEntity"
        super().__init__(esphome, list_callback, state_callback, command_callback)


class ButtonEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesButtonResponse | None],
        # state_callback: Callable[[], api.LightStateResponse | None],
        command_callback: Callable[[api.ButtonCommandRequest], None],
    ):
        self.entity_type = "ButtonEntity"
        super().__init__(esphome, list_callback, None, command_callback)


# input
class TextEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesTextResponse | None],
        state_callback: Callable[[], api.TextStateResponse | None],
        command_callback: Callable[[api.TextCommandRequest], None],
    ):
        self.entity_type = "TextEntity"
        super().__init__(esphome, list_callback, state_callback, command_callback)


# output
class TextSensorEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesTextSensorResponse | None],
        state_callback: Callable[[], api.TextSensorStateResponse | None],
    ):
        self.entity_type = "TextSensorEntity"
        super().__init__(esphome, list_callback, state_callback, None)


class BinaryEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesBinarySensorResponse | None],
        state_callback: Callable[[], api.BinarySensorStateResponse | None],
    ):
        self.entity_type = "BinaryEntity"
        super().__init__(esphome, list_callback, state_callback, None)


class SensorEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesSensorResponse | None],
        state_callback: Callable[[], api.SensorStateResponse | None],
    ):
        self.entity_type = "SensorEntity"
        super().__init__(esphome, list_callback, state_callback, None)
