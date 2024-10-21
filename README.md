# ESPHome Emulator

Pretend to be an ESPHome device with a Python script.

## Why?

Just for fun and to learn protobuf and sockets in Python.

## Installation

```console
$ python3 -m pipx install git+https://github.com/aarongorka/esphome_emulator.git
$ curl -LsO https://raw.githubusercontent.com/aarongorka/esphome_emulator/refs/heads/main/esphome_emulator.service ~/.config/systemd/user/esphome_emulator.service
$ systemctl --user daemon-reload
$ systemctl edit --user esphome_emulator
[Service]
ExecStart=/home/<username>/.local/bin/esphome_emulator # set the path to the executable
Environment="ESPHOME_EMULATOR_API_KEY=<API KEY>"
$ systemctl enable --now --user esphome_emulator
```

## Limitations

  * ~No encryption~
  * ~No authentication~
  * ~No discovery~
  * ~Doesn't handle multiple clients~
  * ~Doesn't integrate with ESPHome dashboard/server, only Home Assistant~
  * ~Only implements sending of sensor data~
  * Limited sensor implementation
  * Spaghetti codebase
