#!/usr/bin/env python
from __future__ import annotations
from typing import Callable
from . import api_pb2 as api
# from aioesphomeapi import api_pb2 as api
import logging

logger = logging.getLogger("esphome_emulator")

class BaseEntity(object):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesMediaPlayerResponse | api.ListEntitiesSelectResponse | api.ListEntitiesLightResponse | api.ListEntitiesButtonResponse | api.ListEntitiesTextResponse | api.ListEntitiesBinarySensorResponse | api.ListEntitiesTextSensorResponse | None],
        state_callback: Callable[[], api.MediaPlayerStateResponse | api.SelectStateResponse | api.LightStateResponse | api.TextStateResponse | api.BinarySensorStateResponse  | api.TextSensorStateResponse | None] | None,
        command_callback: Callable[[api.MediaPlayerCommandRequest | api.SelectCommandRequest | api.LightCommandRequest | api.ButtonCommandRequest], api.MediaPlayerStateResponse | api.SelectStateResponse | api.LightStateResponse | api.TextCommandRequest | None] | None,
    ):
        self.key = self.get_key(esphome)
        self.list_callback = list_callback
        self.state_callback = state_callback
        self.command_callback = command_callback

    def get_key(self, esphome) -> int:
        try:
            key = self.key
        except AttributeError:
            key = max([entity.key for entity in esphome.entities if entity.key is not None] + [-1]) + 1
            logger.debug(f"Setting {self} key to {key}...")
        return key

class MediaPlayerEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesMediaPlayerResponse | None],
        state_callback: Callable[[], api.MediaPlayerStateResponse | None],
        command_callback: Callable[[api.MediaPlayerCommandRequest], api.MediaPlayerStateResponse | None],
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
        command_callback: Callable[[api.SelectCommandRequest], api.SelectStateResponse | None],
    ):
        self.entity_type = "SelectEntity"
        super().__init__(esphome, list_callback, state_callback, command_callback)

class LightEntity(BaseEntity):
    def __init__(
        self,
        esphome,
        list_callback: Callable[[], api.ListEntitiesLightResponse | None],
        state_callback: Callable[[], api.LightStateResponse | None],
        command_callback: Callable[[api.LightCommandRequest ], api.LightStateResponse| None],
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
