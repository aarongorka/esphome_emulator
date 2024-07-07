#!/usr/bin/env python
"""Example implementatino of esphome_emulator."""

from esphome_emulator.esphome_emulator import run, api, GetListsResponse, GetStatesResponse
import socket

def example_get_lists() -> GetListsResponse:
    """Returns a Connected binary sensor."""

    hostname = socket.gethostname()
    response = api.ListEntitiesBinarySensorResponse()
    response.object_id = f"{hostname}.connected"
    response.key = 0
    response.name = "Connected"
    response.unique_id = f"{hostname}.connected"
    response.device_class = "connectivity"
    response.is_status_binary_sensor = True
    # response.disabled_by_default = False
    # response.icon = ""
    response.entity_category = api.EntityCategory.ENTITY_CATEGORY_DIAGNOSTIC

    return [response]

def example_get_states() -> GetStatesResponse:
    """Returns a Connected binary sensor."""

    response = api.BinarySensorStateResponse()
    response.key = 0
    response.state = True
    response.missing_state = False
    return [response]

if __name__ == "__main__":
    run(example_get_lists, example_get_states)
