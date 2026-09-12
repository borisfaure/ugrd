__author__ = "borisfaure"
__version__ = "0.1.0"

from pathlib import Path

from ugrd import InitramfsProtocol
from ugrd.exceptions import ValidationError
from zenlib.util import colorize as c_
from zenlib.util import contains

SESSION_SCRIPT = "dropbear_unlock.sh"


def _process_dropbear_authorized_keys(self: InitramfsProtocol, authorized_keys: Path | str) -> None:
    """Validates the authorized_keys file, then sets dropbear_authorized_keys.
    An empty file would leave no way to log in, so it is rejected."""
    authorized_keys = Path(authorized_keys)
    if not authorized_keys.is_file():
        raise ValidationError(f"[dropbear] authorized_keys file not found: {c_(authorized_keys, 'red')}")
    if not authorized_keys.read_text().strip():
        raise ValidationError(f"[dropbear] authorized_keys file is empty: {c_(authorized_keys, 'red')}")
    self.data["dropbear_authorized_keys"] = authorized_keys


@contains("dropbear_authorized_keys", "dropbear_authorized_keys must be set", raise_exception=True)
def add_dropbear_authorized_keys(self: InitramfsProtocol) -> None:
    """Copies the authorized_keys file to /root/.ssh/authorized_keys in the initramfs."""
    self["copies"] = {
        "dropbear_authorized_keys": {
            "source": self["dropbear_authorized_keys"],
            "destination": "/root/.ssh/authorized_keys",
        }
    }


def dropbear_finalize(self: InitramfsProtocol) -> None:
    """Writes the passwd/group entries dropbear needs, deploys the session script, then
    tightens permissions on the key material.

    The passwd shell must exist in the image, so it matches the init shebang.
    """
    self._write("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", append=True)
    self._write("etc/group", "root:x:0:\ntty:x:5:\n", append=True)

    _deploy_session_script(self)

    self._get_build_path("etc/dropbear").chmod(0o700)
    self._get_build_path("root/.ssh").chmod(0o700)
    self._get_build_path("root/.ssh/authorized_keys").chmod(0o600)


def _deploy_session_script(self: InitramfsProtocol) -> None:
    """Writes the script dropbear forces as the ssh session command.

    It only unlocks; the console init stays PID 1 and does the mount and switch_root.
    The functions it calls come from the profile, sourced by the login shell shebang.
    """
    self._write(
        SESSION_SCRIPT,
        [
            self["shebang"],
            f'einfo "ugrd dropbear remote unlock, module v{__version__}"',
            "crypt_init",
            # the console init is blocked in its own prompt and cannot notice this
            "nudge_crypt_prompt",
            'einfo "Unlock complete, the console init will continue booting"',
        ],
        chmod_mask=0o755,
    )


def nudge_crypt_prompt(self: InitramfsProtocol) -> str:
    """Returns a shell function which SIGINTs any waiting cryptsetup passphrase prompt.

    SIGINT, not SIGKILL, so the shell running the prompt survives. /proc is walked
    because the image has no pgrep, and comm is read rather than cmdline because
    cmdline is NUL separated and there is no tr.
    """
    return """
    for _proc in /proc/[0-9]*; do
        _pid="${_proc##*/}"
        [ "$_pid" = "$$" ] && continue
        read -r _comm < "$_proc/comm" 2>/dev/null || continue
        if [ "$_comm" = "cryptsetup" ]; then
            einfo "Interrupting cryptsetup prompt: $_pid"
            kill -INT "$_pid" 2>/dev/null
        fi
    done
    """


def stop_dropbear(self: InitramfsProtocol) -> str:
    """Returns a shell function which stops the dropbear daemon and any session it spawned.

    Sessions are killed first, or one still at a prompt survives switch_root.
    """
    return """
    dropbear_pid="$(readvar DROPBEAR_PID)"
    if [ -z "$dropbear_pid" ]; then
        ewarn "Unable to read DROPBEAR_PID, not stopping dropbear."
        return
    fi
    for _proc in /proc/[0-9]*; do
        _pid="${_proc##*/}"
        read -r _stat < "$_proc/stat" 2>/dev/null || continue
        # ppid is the second field after the comm field, which is parenthesised and may
        # itself contain spaces -- so split after the last ") " rather than by field number
        _rest="${_stat##*) }"
        # shellcheck disable=SC2086
        set -- $_rest
        _ppid="$2"
        if [ "$_ppid" = "$dropbear_pid" ]; then
            einfo "Stopping dropbear session: $_pid"
            kill "$_pid" 2>/dev/null
        fi
    done
    einfo "Stopping dropbear: $dropbear_pid"
    kill "$dropbear_pid"
    """


def start_dropbear(self: InitramfsProtocol) -> list[str]:
    """Returns the shell lines which start dropbear as a background daemon.

    Not waited on, so the console init continues into its own passphrase prompt.
    The PID is recorded for stop_dropbear.
    """
    # Keys only, no forwarding; -R reuses host keys under /etc/dropbear if any were included
    args = ["-F", "-E", "-R", "-s", "-g", "-j", "-k", "-p", str(self["dropbear_port"])]
    if self["dropbear_args"]:
        args += list(self["dropbear_args"])
    args += ["-c", f"/{SESSION_SCRIPT}"]

    self.logger.info("[dropbear] Server arguments: %s", c_(" ".join(args), "cyan"))

    return [
        f'einfo "Starting dropbear on port: {self["dropbear_port"]}"',
        f"dropbear {' '.join(args)} &",
        "dropbear_pid=$!",
        'setvar DROPBEAR_PID "$dropbear_pid"',
    ]
