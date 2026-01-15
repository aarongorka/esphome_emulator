#!/usr/bin/env python
from __future__ import annotations

# from aioesphomeapi import api_pb2 as api
import logging
from abc import ABC, abstractmethod
from typing import override

from . import api_pb2 as api

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


class BaseEntity[TListEntitiesResponse, TStateResponse, TCommandRequest](ABC):
    def __init__(
        self,
    ):
        self.name: str = type(self).__name__
        self.key: int = self.get_key()

    def get_key(self) -> int:
        try:
            key = self.key
        except AttributeError:
            key = int(
                str(abs(int(hash(self.name))))[:5]
            )  # TODO: real method of generating a unique key
            logger.info(f"Setting {self.name} key to {key}...")
        return key

    @abstractmethod
    def list_callback(self) -> TListEntitiesResponse | None:
        pass

    @abstractmethod
    def state_callback(self) -> TStateResponse | None:
        pass

    @abstractmethod
    def command_callback(
        self, command: TCommandRequest | None
    ) -> TStateResponse | None:
        pass


class MediaPlayerEntity(
    BaseEntity[
        api.ListEntitiesMediaPlayerResponse,
        api.MediaPlayerStateResponse,
        api.MediaPlayerCommandRequest,
    ],
    ABC,
):
    def __init__(self, *args, **kwargs):
        self.entity_type: str = "MediaPlayerEntity"
        super().__init__(*args, **kwargs)


class SelectEntity(
    BaseEntity[
        api.ListEntitiesSelectResponse,
        api.SelectStateResponse,
        api.SelectCommandRequest,
    ],
    ABC,
):
    def __init__(self):
        self.entity_type: str = "SelectEntity"
        super().__init__()


class LightEntity(
    BaseEntity[
        api.ListEntitiesLightResponse, api.LightStateResponse, api.LightCommandRequest
    ],
    ABC,
):
    def __init__(self):
        self.entity_type: str = "LightEntity"
        super().__init__()


class ButtonEntity(
    BaseEntity[api.ListEntitiesButtonResponse, None, api.ButtonCommandRequest], ABC
):
    def __init__(self):
        self.entity_type: str = "ButtonEntity"
        super().__init__()

    @override
    def state_callback(self):
        pass


# input
class TextEntity(
    BaseEntity[
        api.ListEntitiesTextResponse, api.TextStateResponse, api.TextCommandRequest
    ],
    ABC,
):
    def __init__(self):
        self.entity_type: str = "TextEntity"
        super().__init__()


# output
class TextSensorEntity(
    BaseEntity[api.ListEntitiesTextSensorResponse, api.TextSensorStateResponse, None],
    ABC,
):
    def __init__(self):
        self.entity_type: str = "TextSensorEntity"
        super().__init__()

    @override
    def command_callback(self, command: None):
        pass


class BinaryEntity(
    BaseEntity[
        api.ListEntitiesBinarySensorResponse, api.BinarySensorStateResponse, None
    ],
    ABC,
):
    def __init__(self):
        self.entity_type: str = "BinaryEntity"
        super().__init__()

    @override
    def command_callback(self, command: None):
        pass


class SensorEntity(
    BaseEntity[api.ListEntitiesSensorResponse, api.SensorStateResponse, None], ABC
):
    def __init__(self):
        self.entity_type: str = "SensorEntity"
        super().__init__()

    @override
    def command_callback(self, command: None):
        pass
