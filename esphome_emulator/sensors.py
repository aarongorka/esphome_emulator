from __future__ import annotations
from typing import Callable

from dbus.proxies import ProxyObject
from esphome_emulator.entities import MediaPlayerEntity, SelectEntity, LightEntity, ButtonEntity, TextSensorEntity, BinaryEntity
# from esphome_emulator.esphome_emulator import api
from . import api_pb2 as api
import socket
import os
import sh
import logging
import dbus

logger = logging.getLogger("esphome_emulator")

pgrep: Callable[..., str] = sh.pgrep # pyright: ignore
try:
    deadbeef: Callable[..., str] = sh.deadbeef # pyright: ignore
except sh.CommandNotFound:
    pass
try:
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
            media.state = api.MEDIA_PLAYER_STATE_IDLE # seems like this should be api.MEDIA_PLAYER_STATE_NONE but home assistant doesn't like it anymore
            logger.debug("Media is ~none~ idle.")
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
        power = None
        try:
            output: str = ddcutil("getvcp", "d6")
        except:
            logger.debug("Failed to query monitor power state")
            response.state = False
            return response

        try:
            power = output.strip().split(':', 1)[1].split("=")[1].strip(")")
        except:
            logger.debug(f"Could not determine power state of monitor: {output}")

        if power is not None and power != "0x01":
            response.state = False
            logger.debug(f"Power state is {power}, considering off")
            return response
        elif power is not None and power == "0x01":
            logger.debug(f"Monitor is in state {power}, considering it as on")
            response.state = True
        else:
            logger.debug(f"Power state is {power}, something went wrong")
            response.state = False
            return response

        # <blah blah>: current value =     93, max value =   100
        try:
            output: str = ddcutil("getvcp", "10")
            brightness = int(output.split(":")[1].split(",")[0].split("=")[1].strip()) / 100
        except:
            response.state = False
            return response

        logger.debug("Brightness is: %s", brightness)
        response.brightness = float(brightness)
        response.color_mode = api.COLOR_MODE_BRIGHTNESS
        return response

    def list_backlight(self) -> api.ListEntitiesLightResponse | None:
        if os.path.isfile("/usr/bin/ddcutil"):
            try:
                output: str = ddcutil("getvcp", "d6")
                logger.debug("Successfully got backlight state: %s", output)
            except:
                logger.debug("Error getting displays, not enabling backlight sensor.")
                return None

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

        if request.has_state:
            if request.state == False:
                logger.debug("Turning the monitor off...")
                ddcutil("setvcp", "d6", "5")
            if request.state == True and request.has_brightness == False:
                logger.debug("Turning the monitor on...")
                ddcutil("setvcp", "d6", "1")

        if request.has_brightness:
            brightness = int(request.brightness * 100)
            logger.debug("Setting brightness to: %s", brightness)
            ddcutil("setvcp", "10", brightness)

        return self.get_backlight_state()

# VCP code 0xac (Horizontal frequency          ): 29220 hz
# VCP code 0xae (Vertical frequency            ): 239.90 hz


class MonitorSelectEntity(SelectEntity):
    def __init__(self, esphome):
        # These are the values we need to send for `setvcp`
        self.set_inputs = {
            "0x11": "HDMI 1", # can actually send anything other than the two below
            "0x0f": "DisplayPort 1",
            "0x10": "DisplayPort 2",
        }
        # These are the values returned when you `getvcp`
        self.get_inputs = {
            "0x01": "HDMI 1", # this code is actually VGA-1
            "0x03": "DisplayPort 1", # this code is actually DVI-1
            "0x04": "DisplayPort 2", # this code is actually DVI-2
        }
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
            command_callback=self.command_callback,
        )

    def truncate_name_to_fit(self, sink: str, count: int) -> str:
        name_length_allowed = int(62/count)
        return sink[:name_length_allowed]

    def list_callback(self) -> api.ListEntitiesSelectResponse | None:
        if os.path.isfile("/usr/bin/ddcutil"):
            try:
                output: str = ddcutil("getvcp", "d6")
                logger.debug("Successfully got backlight state: %s", output)
            except:
                logger.debug("Error getting displays, not enabling backlight sensor.")
                return None

            hostname = socket.gethostname()
            response = api.ListEntitiesSelectResponse()
            response.key = self.key
            response.unique_id = f"{hostname}.backlight"
            response.object_id = f"{hostname}.backlight"
            response.icon = "mdi:monitor"
            response.name = "Input Source"

            input_names: list[str] = sorted(set([v for k, v in self.get_inputs.items()]))
            # Exactly 64 characters (bytes) allowed? TODO
            response.options.extend([self.truncate_name_to_fit(x, len(input_names)) for x in input_names])
            logger.debug("options: %s", response.options)
            return response

    def state_callback(self) -> api.SelectStateResponse:
        response = api.SelectStateResponse()
        response.key = self.key
        output = ""
        try:
            output = ddcutil("getvcp", "60")
            # VCP code 0x60 (Input Source                  ): DVI-1 (sl=0x03)
            current_code = output.split(':')[1].split('=')[1].rstrip().rstrip(")")
        except:
            logger.debug(f"Failed to parse output: {output}")
            response.missing_state = True
            return response

        current_input = [v for k, v in self.get_inputs.items() if k == current_code]
        if current_input:
            response.state = current_input[0]
        else:
            logger.debug(f"Could not determine current input from output: {output}")
        return response

    def command_callback(self, request: api.SelectCommandRequest):
        logger.debug(f"Got command: {request}")
        matches = [k for k, v in self.set_inputs.items() if v == request.state]
        if len(matches) > 0:
            desired_input = matches[0]
            logger.debug(f"Setting display to {desired_input}...")
            ddcutil("setvcp", "60", desired_input)
        else:
            logger.error(f"Failed to find matching input for {request} and {self.set_inputs}")
        return self.state_callback()


class SuspendButtonEntity(ButtonEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            command_callback=self.command_callback,
        )
        self.key = 2
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

    def command_callback(self, request: api.ButtonCommandRequest):
        logger.debug("Suspending, not that you're going to see this :)")
        sh.sudo.systemctl("suspend") # pyright: ignore

class PowerOffButtonEntity(ButtonEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            command_callback=self.command_callback,
        )
        self.key = 1
        return

    def list_callback(self) -> api.ListEntitiesButtonResponse | None:
        if os.path.isfile("/usr/bin/systemctl"):
            response = api.ListEntitiesButtonResponse()
            response.key = self.key
            hostname = socket.gethostname()
            response.object_id = f"{hostname}.poweroff"
            response.unique_id = f"{hostname}.poweroff"
            response.name = "Power Off"
            response.icon = "mdi:power"
            # response.disabled_by_default = False
            return response

    def command_callback(self, request: api.ButtonCommandRequest):
        logger.debug("Powering off, not that you're going to see this :)")
        sh.sudo.systemctl("poweroff") # pyright: ignore

class MprisMixin():
    def __init__(self, *args, **kwargs):
        try:
            self.bus: dbus.SessionBus = dbus.SessionBus()
            logger.debug(f"Got bus...")

            self.dbus_introspection = self.bus.get_object(object_path='/org/freedesktop/DBus', bus_name='org.freedesktop.DBus')
            self.dbus_introspection_interface = dbus.Interface(self.dbus_introspection, "org.freedesktop.DBus")

            self.mprises: dict[str, ProxyObject] = {}
            self.mpris_properties_interfaces: dict[str, dbus.Interface] = {}
            self.mpris_player_interfaces: dict[str, dbus.Interface] = {}
        except:
            logger.warning("Couldn't set up dbus session and get interfaces...")
        super().__init__(*args, **kwargs)

    def get_mpris(self, mpris_name: str) -> ProxyObject:
        if self.mprises.get(mpris_name) is None:
            mpris = self.bus.get_object(mpris_name, "/org/mpris/MediaPlayer2")
            logger.debug("Got mpris object for %s...", mpris_name)
            self.mprises[mpris_name] = mpris
        else:
            mpris = self.mprises[mpris_name]
        return mpris

    def get_mpris_properties_interface(self, mpris_name: str) -> dbus.Interface:
        if self.mpris_properties_interfaces.get(mpris_name) is None:
            mpris = self.get_mpris(mpris_name)

            mpris_properties_interface = dbus.Interface(mpris, "org.freedesktop.DBus.Properties")
            logger.debug("Got mpris properties interface for %s...", mpris_name)
            self.mpris_properties_interfaces[mpris_name] = mpris_properties_interface
        else:
            mpris_properties_interface = self.mpris_properties_interfaces[mpris_name]
        return mpris_properties_interface

    def get_mpris_player_interface(self, mpris_name: str) -> dbus.Interface:
        if self.mpris_player_interfaces.get(mpris_name) is None:
            mpris = self.get_mpris(mpris_name)

            mpris_player_interface = dbus.Interface(mpris, "org.mpris.MediaPlayer2.Player")
            logger.debug("Got mpris player interface for %s...", mpris_name)
            self.mpris_player_interfaces[mpris_name] = mpris_player_interface
        else:
            mpris_player_interface = self.mpris_player_interfaces[mpris_name]
        return mpris_player_interface

    def get_mpris_names(self) -> list[str]:
        names = self.dbus_introspection_interface.ListNames()
        mpris_names = [str(x) for x in names if "org.mpris.MediaPlayer2" in str(x)]
        return mpris_names

    def refresh_interfaces(self) -> None:
        mpris_names = self.get_mpris_names()
        for mpris_name in mpris_names:
            self.get_mpris_properties_interface(mpris_name)
            self.get_mpris_player_interface(mpris_name)

    def get_playing_mpris_names(self, mpris_names: list[str] | None = None) -> list[str]:
        if mpris_names is None:
            mpris_names = self.get_mpris_names()

        playing: list[str] = [mpris_name for mpris_name in mpris_names if self.get_mpris_properties_interface(mpris_name).Get("org.mpris.MediaPlayer2.Player", "PlaybackStatus") == "Playing"]

        return playing

    def get_paused_mpris_names(self, mpris_names: list[str] | None = None) -> list[str]:
        if mpris_names is None:
            mpris_names = self.get_mpris_names()

        paused: list[str] = [mpris_name for mpris_name in mpris_names if self.get_mpris_properties_interface(mpris_name).Get("org.mpris.MediaPlayer2.Player", "PlaybackStatus") == "Paused"]

        return paused

    def get_priority_player_name(self) -> str | None:
        """Prioritise playing players, paused players and then just grab the first one available."""

        mpris_names = self.get_mpris_names()
        playing = self.get_playing_mpris_names(mpris_names)

        if len(mpris_names) == 0:
            logger.debug("No mpris found on dbus?")
            return None
        elif len(playing) > 0:
            if len(playing) > 1:
                logger.warning("Multiple players playing at once? %s", playing)
            mpris_name = playing[0]
            logger.debug("Got playing mpris: %s", mpris_name)
        else:
            paused = self.get_paused_mpris_names(mpris_names)

            if len(paused) > 0:
                if len(paused) > 1:
                    logger.debug("Multiple players paused at once? %s", paused)
                mpris_name = paused[0]
                logger.info("Got paused mpris: %s", mpris_name)
            else:
                mpris_name = mpris_names[0]
                logger.debug("Nothing playing, just getting first active player: %s", mpris_name)
        return mpris_name

class MprisMediaPlayerEntity(MprisMixin, MediaPlayerEntity):

    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
            command_callback=self.command_callback,
        )

    def state_callback(self) -> api.MediaPlayerStateResponse:
        """Get MPRIS player state."""

        media = api.MediaPlayerStateResponse()
        media.key = self.key

        mpris_name = self.get_priority_player_name()
        if mpris_name is None:
            media.state = api.MEDIA_PLAYER_STATE_IDLE
        else:
            mpris_properties_interface = self.get_mpris_properties_interface(mpris_name)

            playback_status = mpris_properties_interface.Get("org.mpris.MediaPlayer2.Player", "PlaybackStatus")
            if playback_status == "Stopped":
                media.state = api.MEDIA_PLAYER_STATE_IDLE
                logger.debug("Media is ~none~ idle.")
            elif playback_status == "Paused":
                media.state = api.MEDIA_PLAYER_STATE_PAUSED
                logger.debug("Media is paused.")
            elif playback_status == "Playing":
                media.state = api.MEDIA_PLAYER_STATE_PLAYING
                logger.debug("Media is playing.")
            else:
                media.state = api.MEDIA_PLAYER_STATE_IDLE

            volume = mpris_properties_interface.Get("org.mpris.MediaPlayer2.Player", "Volume")
            if volume == 0.0:
                media.muted
            else:
                media.volume = volume

        return media

    def command_callback(self, command: api.MediaPlayerCommandRequest) -> api.MediaPlayerStateResponse:

        mpris_name = self.get_priority_player_name()
        if mpris_name is None:
            logger.warning("Can't run an action if there's no players available?")
        else:
            mpris_properties_interface = self.get_mpris_properties_interface(mpris_name)
            mpris_player_interface = self.get_mpris_player_interface(mpris_name)

            if command.volume != 0:
                mpris_properties_interface.Set("org.mpris.MediaPlayer2.Player", "Volume", command.volume)

            if command.command == api.MEDIA_PLAYER_COMMAND_STOP:
                mpris_player_interface.Stop()

            if command.command == api.MEDIA_PLAYER_COMMAND_PAUSE:
                mpris_player_interface.Pause()

            if command.command == api.MEDIA_PLAYER_COMMAND_PLAY:
                if mpris_properties_interface.Get("org.mpris.MediaPlayer2.Player", "PlaybackStatus") == "Paused":
                    mpris_player_interface.PlayPause()

            if command.command == api.MEDIA_PLAYER_COMMAND_MUTE:
                mpris_properties_interface.Set("org.mpris.MediaPlayer2.Player", "Volume", 0.0)

            if command.command == api.MEDIA_PLAYER_COMMAND_UNMUTE:
                mpris_properties_interface.Set("org.mpris.MediaPlayer2.Player", "Volume", 1.0) # idk

        state = self.state_callback()
        return state

    def list_callback(self) -> api.ListEntitiesMediaPlayerResponse | None:
        """Determines if dbus is available and returns an entity if true."""

        try:
            names = self.get_mpris_names()
            logger.debug("Successfully tested dbus connection: %s", names)
        except:
            logger.exception("Couldn't get mpris names?")
            return None

        hostname = socket.gethostname()

        media = api.ListEntitiesMediaPlayerResponse()
        media.key = self.key
        media.object_id = f"{hostname}.media"
        media.unique_id = f"{hostname}.media"
        media.name = "Media"
        media.supports_pause = True

        return media

class MprisNowPlayingEntity(MprisMixin, TextSensorEntity):

    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
        )
        self.key = 9
        return

    def list_callback(self) -> api.ListEntitiesTextSensorResponse | None:
        """Determines if dbus is available and returns an entity if true."""

        try:
            names = self.get_mpris_names()
            logger.debug("Successfully tested dbus connection: %s", names)
        except:
            logger.exception("Couldn't get mpris names?")
            return None

        hostname = socket.gethostname()

        response = api.ListEntitiesTextSensorResponse()
        response.key = self.key
        response.object_id = f"{hostname}.media_now_playing"
        response.unique_id = f"{hostname}.media_now_playing"
        response.name = "Media Now Playing"
        response.icon = "mdi:play"

        return response

    def state_callback(self) -> api.TextSensorStateResponse | None:

        response = api.TextSensorStateResponse()
        response.key = self.key

        mpris_name = self.get_priority_player_name()

        if mpris_name is not None:
            mpris_properties_interface = self.get_mpris_properties_interface(mpris_name)

            props = mpris_properties_interface.Get("org.mpris.MediaPlayer2.Player", "Metadata")
            artist = "".join([str(x) for x in props.get("xesam:artist", [])])
            title = str(props.get("xesam:title"))
            if not title:
                logger.warning("Could not get title or artist? %s", props)
                response.missing_state = True
            else:
                if artist:
                    response.state = f"{artist} - {title}"
                    return response
                else:
                    response.state = title
                    return response
        else:
            response.missing_state = True
            logger.debug("No players found...")

        return response

class NowPlayingEntity(TextSensorEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
        )
        self.key = 9
        return

    def list_callback(self) -> api.ListEntitiesTextSensorResponse | None:
        """Determines if deadbeef is installed and returns an entity if true."""

        if os.path.isfile("/usr/bin/deadbeef"):

            hostname = socket.gethostname()

            response = api.ListEntitiesTextSensorResponse()
            response.key = self.key
            response.object_id = f"{hostname}.media_now_playing"
            response.unique_id = f"{hostname}.media_now_playing"
            response.name = "Media Now Playing"
            response.icon = "mdi:play"

            return response
        else:
            return None

    def state_callback(self) -> api.TextSensorStateResponse | None:

        response = api.TextSensorStateResponse()
        response.key = self.key

        try:
            pgrep(f="deadbeef")
        except Exception:
            response.missing_state = True
            logger.debug("Now playing has no state.")
            return response

        if deadbeef("--nowplaying-tf", '%ispaused%') == "1":
            response.missing_state = True
        elif deadbeef("--nowplaying-tf", '%isplaying%') == "1":
            logger.debug("Media is playing, getting metadata...")
            try:
                output = deadbeef("--nowplaying-tf", '%artist% - %title%')
            except Exception:
                response.missing_state = True
                logger.debug("Could not get metadata?")
                return response

            if output:
                logger.info(f"Returning {output}")
                response.state = str(output.strip())[:64]
            else:
                logger.warning(f"Returning missing state")
                response.missing_state = True

        return response

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

class GamemodeTextSensorEntity(TextSensorEntity):
    def __init__(self, esphome):
        self.bus = None
        self.gamemode = None
        self.gamemode_interface = None
        self.gamemode_properties_interface = None
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
        )

    def get_bus(self) -> dbus.SessionBus:
        if self.bus is None:
            bus: dbus.SessionBus = dbus.SessionBus()
            logger.debug(f"Got bus...")
            self.bus = bus
            return bus
        else:
            return self.bus

    def get_interfaces(self) -> tuple[dbus.Interface, dbus.Interface]:
        if self.gamemode_interface is None or self.gamemode_properties_interface is None:
            bus = self.get_bus()
            gamemode = bus.get_object(object_path='/com/feralinteractive/GameMode', bus_name='com.feralinteractive.GameMode')
            gamemode_interface = dbus.Interface(self.gamemode, "com.feralinteractive.GameMode")
            gamemode_properties_interface = dbus.Interface(self.gamemode, "org.freedesktop.DBus.Properties")

            self.gamemode = gamemode
            self.gamemode_interface = gamemode_interface
            self.gamemode_properties_interface = gamemode_properties_interface

            return gamemode_interface, gamemode_properties_interface
        else:
            return self.gamemode_interface, self.gamemode_properties_interface

    def get_games(self) -> list[str]:
        gamemode_interface, _ = self.get_interfaces()
        response = gamemode_interface.ListGames()
        # games_list = [str(x) for x in [x[0] for x in response]]
        return [str(x) for x in [x[1] for x in response]]

    def list_callback(self) -> api.ListEntitiesTextSensorResponse | None:
        """Determines if gamemode is running and returns an entity."""

        try:
            self.get_games()
        except:
            logger.exception("Failed to get gamemode games, not enabling sensor.")
            return None

        hostname = socket.gethostname()

        response = api.ListEntitiesTextSensorResponse()
        response.key = self.key
        response.object_id = f"{hostname}.game_now_playing"
        response.unique_id = f"{hostname}.game_now_playing"
        response.name = "Game Now Playing"
        response.icon = "mdi:controller"

        return response

    def state_callback(self) -> api.TextSensorStateResponse | None:
        response = api.TextSensorStateResponse()
        response.key = self.key

        games_list = self.get_games()

        if len(games_list) < 1:
            return response

        logger.info("Games list: %s", games_list)
        # game = bus.get_object(object_path='/com/feralinteractive/GameMode', bus_name='com.feralinteractive.GameMode')
        # game_properties_interface = dbus.Interface(game, "org.freedesktop.DBus.Properties")
        # game_interface = dbus.Interface(game, "com.feralinteractive.GameMode")
        # games_list = game_interface.ListGames()
        game_path = games_list[0]

        game_path_object = self.bus.get_object(object_path=game_path, bus_name='com.feralinteractive.GameMode')
        game_path_interface = dbus.Interface(game_path_object, "org.freedesktop.DBus.Properties")
        props = game_path_interface.GetAll("com.feralinteractive.GameMode.Game")

        executable_fullpath = f"{props['Executable']}"
        executable_filename = executable_fullpath.rsplit("/")
        game_name = executable_filename[-1].rsplit(".exe")[0]
        response.state = game_name
        return response



class StatusEntity(BinaryEntity):
    def __init__(self, esphome):
        super().__init__(
            esphome,
            list_callback=self.list_callback,
            state_callback=self.state_callback,
        )
        self.key = 1
        return

    def list_callback(self) -> api.ListEntitiesBinarySensorResponse | None:
        hostname = socket.gethostname()
        response = api.ListEntitiesBinarySensorResponse()
        response.key = self.key
        response.unique_id = f"{hostname}.status"
        response.object_id = f"{hostname}.status"
        response.name = "Status"
        response.is_status_binary_sensor = True
        response.entity_category = api.ENTITY_CATEGORY_DIAGNOSTIC
        return response

    def state_callback(self) -> api.BinarySensorStateResponse | None:
        response = api.BinarySensorStateResponse()
        response.key = self.key
        response.state = True
        return response
