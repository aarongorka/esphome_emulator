from __future__ import annotations
from esphome_emulator.entities import MediaPlayerEntity, SelectEntity, LightEntity
from esphome_emulator.esphome_emulator import  api
import socket
from sh import pgrep # pyright: ignore
try:
    from sh import deadbeef, pactl # pyright: ignore
except:
    pass
try:
    from sh import ddcutil # pyright: ignore
except:
    pass
import os

def get_deadbeef_state() -> api.MediaPlayerStateResponse:
    """Get deadbeef state (through CLI lol)."""

    media = api.MediaPlayerStateResponse()
    # media.key = 0

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

def handle_command_deadbeef(command: api.MediaPlayerCommandRequest) -> api.MediaPlayerStateResponse:
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

    media = get_deadbeef_state()
    return media

def list_deadbeef() -> api.ListEntitiesMediaPlayerResponse | None:
    """Determines if deadbeef is installed and returns an entity if true."""

    if os.path.isfile("/usr/bin/deadbeef"):

        hostname = socket.gethostname()

        media = api.ListEntitiesMediaPlayerResponse()
        media.object_id = f"{hostname}.media"
        media.unique_id = f"{hostname}.media"
        media.name = "Media"
        media.supports_pause = True

        return media
    else:
        return None

class DeadbeefEntity(MediaPlayerEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=list_deadbeef,
            state_callback=get_deadbeef_state,
            command_callback=handle_command_deadbeef,
        )

def truncate_name_to_fit(sink: str, count: int) -> str:
    name_length_allowed = int(62/count)
    return sink.removeprefix("alsa_output.")[:name_length_allowed]

def get_sinks():
    return [x.split("\t")[1] for x in pactl("list", "short", "sinks").strip().split('\n')]

def list_audio() -> api.ListEntitiesSelectResponse | None:
    if os.path.isfile("/usr/bin/pactl"):
        hostname = socket.gethostname()

        response = api.ListEntitiesSelectResponse()
        response.name = "Audio Outputs"
        response.object_id = f"{hostname}.outputs"
        response.unique_id = f"{hostname}.outputs"

        # Dynamic icon doesn't seem to work unfortunately...
        sink = get_default_sink()
        if "usb" in sink:
            response.icon = "mdi:usb"
        elif "ac3" in sink:
            response.icon = "mdi:toslink"

        sinks: list[str] = get_sinks()
        # Exactly 64 characters (bytes) allowed? TODO
        response.options.extend([truncate_name_to_fit(x, len(sinks)) for x in sinks])
        print("options:", response.options)

        return response

def audio_command(request: api.SelectCommandRequest):
    sinks = get_sinks()
    try:
        desired_sink = [x for x in sinks if request.state in x]
        print(f"Setting default sink to {desired_sink}...")
        pactl("set-default-sink", desired_sink)
        print(f"Default sink set to {desired_sink}.")
    except AttributeError:
        pass

    return get_audio_state()

def get_default_sink():
    pactl_info = {k: v for k, v in [x.split(": ") for x in pactl("info").strip().split("\n")]}
    default_sink = pactl_info.get("Default Sink", "")
    return default_sink

def get_audio_state() -> api.SelectStateResponse:
    response = api.SelectStateResponse()
    sinks = get_sinks()
    default_sink = get_default_sink().removeprefix("alsa_output.")
    default_sink_truncated = truncate_name_to_fit(default_sink, len(sinks))
    print("Default sink:", default_sink_truncated)
    response.state = default_sink_truncated
    return response


class AudioOutputEntity(SelectEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=list_audio,
            state_callback=get_audio_state,
            command_callback=audio_command,
        )

def get_backlight_state():
    response = api.LightStateResponse()
    # <blah blah>: current value =     93, max value =   100
    output: str = ddcutil("getvcp", "10")
    response.brightness = int(output.split(":")[1].split(",")[0].split("=")[1].strip())
    return response

def list_backlight():
    if os.path.isfile("/usr/bin/ddcutil"):
        hostname = socket.gethostname()
        response = api.ListEntitiesLightResponse()
        response.unique_id = f"{hostname}.backlight"
        response.object_id = f"{hostname}.backlight"
        response.icon = "mdi:monitor"
        response.supported_color_modes.extend([api.COLOR_MODE_BRIGHTNESS])
        return response

def handle_backlight_command(request):
    request = api.LightCommandRequest()

    ddcutil("setvcp", "10", request.brightness)
    return get_backlight_state()

class MonitorBacklightEntity(LightEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=list_backlight,
            state_callback=get_backlight_state,
            command_callback=handle_backlight_command,
        )
