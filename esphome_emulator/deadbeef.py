from __future__ import annotations
from typing import Callable
from esphome_emulator.entities import MediaPlayerEntity, SelectEntity, LightEntity, ButtonEntity, TextEntity, BinaryEntity
from esphome_emulator.esphome_emulator import  api
import socket
import os
import sh
import logging

logger = logging.getLogger("esphome_emulator")
# logger.setLevel(logging.INFO)
# logger.propagate = False

pgrep: Callable[..., str] = sh.pgrep # pyright: ignore
try:
    deadbeef: Callable[..., str] = sh.deadbeef # pyright: ignore
    pactl: Callable[..., str] = sh.pactl # pyright: ignore
except sh.CommandNotFound:
    pass
try:
    ddcutil: Callable[..., str] = sh.ddcutil # pyright: ignore
except sh.CommandNotFound:
    pass
try:
    gamemoded: Callable[..., str] = sh.gamemoded # pyright: ignore
except sh.CommandNotFound:
    pass

class DeadbeefEntity(MediaPlayerEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_deadbeef,
            state_callback=self.get_deadbeef_state,
            command_callback=self.handle_command_deadbeef,
        )

    def get_deadbeef_state(self) -> api.MediaPlayerStateResponse:
        """Get deadbeef state (through CLI lol)."""

        media = api.MediaPlayerStateResponse()
        media.key = self.key
        try:
            pgrep(f="deadbeef")
        except Exception:
            media.state = api.MEDIA_PLAYER_STATE_NONE
            logger.debug("Media is none.")
            return media

        if deadbeef("--nowplaying-tf", '%ispaused%') == "1":
            media.state = api.MEDIA_PLAYER_STATE_PAUSED
            logger.debug("Media is paused.")
        elif deadbeef("--nowplaying-tf", '%isplaying%') == "1":
            media.state = api.MEDIA_PLAYER_STATE_PLAYING
            logger.debug("Media is playing.")
        else:
            media.state = api.MEDIA_PLAYER_STATE_IDLE
            logger.debug("Media is idle.")

        volume = int(deadbeef("--volume").split(' ')[0].strip("%"))/100 or None
        if volume is not None:
            media.volume = volume
            if volume == 0:
                media.muted = True
            else:
                media.muted = False

        return media

    def handle_command_deadbeef(self, command: api.MediaPlayerCommandRequest) -> api.MediaPlayerStateResponse:
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

        media = self.get_deadbeef_state()
        return media

    def list_deadbeef(self) -> api.ListEntitiesMediaPlayerResponse | None:
        """Determines if deadbeef is installed and returns an entity if true."""

        if os.path.isfile("/usr/bin/deadbeef"):

            hostname = socket.gethostname()

            media = api.ListEntitiesMediaPlayerResponse()
            media.key = self.key
            media.object_id = f"{hostname}.media"
            media.unique_id = f"{hostname}.media"
            media.name = "Media"
            media.supports_pause = True

            return media
        else:
            return None

class AudioOutputEntity(SelectEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_audio,
            state_callback=self.get_audio_state,
            command_callback=self.audio_command,
        )

    def truncate_name_to_fit(self, sink: str, count: int) -> str:
        name_length_allowed = int(62/count)
        return sink.removeprefix("alsa_output.")[:name_length_allowed]

    def get_sinks(self):
        return [x.split("\t")[1] for x in pactl("list", "short", "sinks").strip().split('\n')]


    def list_audio(self) -> api.ListEntitiesSelectResponse | None:
        if os.path.isfile("/usr/bin/pactl"):
            hostname = socket.gethostname()

            response = api.ListEntitiesSelectResponse()
            response.key = self.key
            response.name = "Audio Outputs"
            response.object_id = f"{hostname}.outputs"
            response.unique_id = f"{hostname}.outputs"

            # Dynamic icon doesn't seem to work unfortunately...
            sink = self.get_default_sink()
            if "usb" in sink:
                response.icon = "mdi:usb"
            elif "ac3" in sink:
                response.icon = "mdi:toslink"

            sinks: list[str] = self.get_sinks()
            # Exactly 64 characters (bytes) allowed? TODO
            response.options.extend([self.truncate_name_to_fit(x, len(sinks)) for x in sinks])
            logger.debug("options: %s", response.options)

            return response

    def audio_command(self, request: api.SelectCommandRequest):
        sinks = self.get_sinks()
        try:
            desired_sink = [x for x in sinks if request.state in x]
            logger.debug(f"Setting default sink to {desired_sink}...")
            pactl("set-default-sink", desired_sink)
            logger.debug(f"Default sink set to {desired_sink}.")
        except AttributeError:
            pass

        return self.get_audio_state()

    def get_default_sink(self):
        pactl_info = {k: v for k, v in [x.split(": ") for x in pactl("info").strip().split("\n")]}
        default_sink = pactl_info.get("Default Sink", "")
        return default_sink

    def get_audio_state(self) -> api.SelectStateResponse:
        response = api.SelectStateResponse()
        response.key = self.key
        sinks = self.get_sinks()
        default_sink = self.get_default_sink().removeprefix("alsa_output.")
        default_sink_truncated = self.truncate_name_to_fit(default_sink, len(sinks))
        # logger.debug("Default sink: %s", default_sink_truncated.strip())
        response.state = default_sink_truncated
        return response


class MonitorBacklightEntity(LightEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_backlight,
            state_callback=self.get_backlight_state,
            command_callback=self.handle_backlight_command,
        )

    def get_backlight_state(self) -> api.LightStateResponse:
        response = api.LightStateResponse()
        response.key = self.key
        # <blah blah>: current value =     93, max value =   100
        try:
            output: str = ddcutil("getvcp", "10")
            brightness = int(output.split(":")[1].split(",")[0].split("=")[1].strip()) / 100
        except:
            response.state = False
            return response
        logger.debug("Brightness is: %s", brightness)
        response.brightness = float(brightness)
        if brightness > 0:
            response.state = True
        else:
            response.state = False
        response.color_mode = api.COLOR_MODE_BRIGHTNESS
        return response

    def list_backlight(self) -> api.ListEntitiesLightResponse | None:
        if os.path.isfile("/usr/bin/ddcutil"):
            hostname = socket.gethostname()
            response = api.ListEntitiesLightResponse()
            response.key = self.key
            response.unique_id = f"{hostname}.backlight"
            response.object_id = f"{hostname}.backlight"
            response.icon = "mdi:monitor"
            response.name = "Display Backlight"
            response.legacy_supports_brightness = True
            response.supported_color_modes.extend([api.COLOR_MODE_BRIGHTNESS])
            return response

    def handle_backlight_command(self, request) -> api.LightStateResponse:
        """Handle light commands."""

        if request.has_brightness:
            brightness = int(request.brightness * 100)
            logger.debug("Setting brightness to: %s", brightness)
            ddcutil("setvcp", "10", brightness)

        if request.has_state:
            if request.state == False:
                logger.debug("Setting brightness to 0 (off)")
                ddcutil("setvcp", "10", "0")
            if request.state == True and request.has_brightness == False:
                ddcutil("setvcp", "10", "100")

        state = self.get_backlight_state()
        return state

# getvcp 60
# VPC code 0x60 (Input Source      ): DVI-1 (sl=0x03)

class SuspendButtonEntity(ButtonEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            # state_callback=self.state_callback,
            command_callback=self.command_callback,
        )
        return

    def list_callback(self) -> api.ListEntitiesButtonResponse | None:
        if os.path.isfile("/usr/bin/systemctl"):
            response = api.ListEntitiesButtonResponse()
            response.key = self.key
            hostname = socket.gethostname()
            response.object_id = f"{hostname}.suspend"
            response.unique_id = f"{hostname}.suspend"
            response.name = "Suspend"
            response.icon = "mdi:power-sleep"
            response.disabled_by_default = False
            return response

    # def state_callback(self):
    #     logger.debug("Why was this called, a button can't have state...")
    #     return None

    def command_callback(self, request: api.ButtonCommandRequest):
        logger.debug("Suspending, not that you're going to see this :)")
        sh.sudo.systemctl("suspend") # pyright: ignore

class GamingStatusEntity(BinaryEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
        )
        return

    def list_callback(self) -> api.ListEntitiesBinarySensorResponse | None:
        if os.path.isfile("/usr/bin/gamemoded"):
            try:
                gamemoded("-s")
            except Exception:
                logger.error("Failed to run gamemoded -s, not adding sensor...")
                return None
            hostname = socket.gethostname()
            response = api.ListEntitiesBinarySensorResponse()
            response.key = self.key
            response.unique_id = f"{hostname}.gamemode_status"
            response.object_id = f"{hostname}.gamemode_status"
            response.icon = "mdi:controller"
            response.name = "Gaming"
            return response

    def state_callback(self) -> api.BinarySensorStateResponse| None:

        response = api.BinarySensorStateResponse()
        response.key = self.key
        output = gamemoded("-s").strip()
        logger.debug(f"gamemoded output: {output}")
        if output.find("gamemode is active") == 0:
            response.state = True
        elif output.find("gamemode is inactive") == 0:
            response.state = False
        else:
            response.missing_state = True
        return response
