#!/usr/bin/env python
"""Example implementatino of esphome_emulator."""

from esphome_emulator.esphome_emulator import GetListsResponse, GetStatesResponse, run, api
import socket
from sh import deadbeef, pgrep # pyright: ignore

def example_get_lists() -> GetListsResponse:
    """Returns a Connected binary sensor."""

    hostname = socket.gethostname()
    connected = api.ListEntitiesBinarySensorResponse()
    connected.object_id = f"{hostname}.connected"
    connected.key = 0
    connected.name = "Connected"
    connected.unique_id = f"{hostname}.connected"
    connected.device_class = "connectivity"
    connected.is_status_binary_sensor = True
    connected.entity_category = api.EntityCategory.ENTITY_CATEGORY_DIAGNOSTIC

    # backlight = api.ListEntitiesLightResponse()
    # backlight.object_id = f"{hostname}.backlight"
    # backlight.key = 0
    # backlight.name = "Backlight"
    # backlight.unique_id = f"{hostname}.backlight"
    # # backlight.supported_color_modes = api.COLOR_MODE_BRIGHTNESS

    media = api.ListEntitiesMediaPlayerResponse()
    media.object_id = f"{hostname}.media"
    media.unique_id = f"{hostname}.media"
    media.name = "Media"
    media.supports_pause = True

    lists = [
        connected,
        # backlight,
        media,
    ]

    return lists

def get_media_state() -> api.MediaPlayerStateResponse:
    """Get deadbeef state (through CLI lol)."""

    media = api.MediaPlayerStateResponse()
    media.key = 0

    try:
        pgrep(f="deadbeef")
    except Exception:
        media.state = api.MEDIA_PLAYER_STATE_NONE
        print("Media is none.")
        return media

    if deadbeef("--nowplaying-tf", '%ispaused%') == "1":
        media.state = api.MEDIA_PLAYER_STATE_PAUSED
        print("Media is paused.")
    elif deadbeef("--nowplaying-tf", '%isplaying%') == "1":
        media.state = api.MEDIA_PLAYER_STATE_PLAYING
        print("Media is playing.")
    else:
        media.state = api.MEDIA_PLAYER_STATE_IDLE
        print("Media is idle.")

    volume = int(deadbeef("--volume").split(' ')[0].strip("%"))/100 or None # pyright: ignore
    if volume is not None:
        media.volume = volume
        if volume == 0:
            media.muted = True
        else:
            media.muted = False

    return media

def example_get_states() -> GetStatesResponse:
    """Returns a Connected binary sensor."""

    connected = api.BinarySensorStateResponse()
    connected.key = 0
    connected.state = True
    connected.missing_state = False

    # backlight = api.LightStateResponse()
    # backlight.key = 0
    # backlight.state = True
    # backlight.brightness = 100
    # backlight.color_mode = api.COLOR_MODE_BRIGHTNESS

    states = [
        connected,
        # backlight,
        get_media_state()
    ]

    return states

def example_handle_media_command(command: api.MediaPlayerCommandRequest) -> list[api.MediaPlayerStateResponse]:

    if command.volume != 0:
        deadbeef("--volume", command.volume*100)

    if command.command == api.MEDIA_PLAYER_COMMAND_STOP:
        deadbeef("--stop")

    if command.command == api.MEDIA_PLAYER_COMMAND_PAUSE:
        deadbeef("--play-pause")

    if command.command == api.MEDIA_PLAYER_COMMAND_PLAY:
        if deadbeef("--nowplaying-tf", '%ispaused%') == "1":
            deadbeef("--play-pause")

    if command.command == api.MEDIA_PLAYER_COMMAND_MUTE:
        deadbeef("--volume", "0")

    if command.command == api.MEDIA_PLAYER_COMMAND_UNMUTE:
        deadbeef("--volume", "100") # idk

    media = get_media_state()
    return [media]

if __name__ == "__main__":
    run(example_get_lists, example_get_states, example_handle_media_command)
