#!/usr/bin/env python3
"""Phase-scoped YubiKey programmer using yubikey-manager public APIs."""

from __future__ import annotations

import json
import struct
import sys
from importlib.metadata import version


def fail(message: str) -> None:
    print(json.dumps({"ok": False, "error": message}), file=sys.stderr)
    raise SystemExit(1)


def validate(data: object) -> dict:
    if not isinstance(data, dict):
        fail("descriptor must be an object")
    required = {
        "serial", "management_algorithm", "management_key", "pin", "puk",
        "slot1", "slot2", "fido_pin", "derivation_profile", "scope",
    }
    if set(data) != required:
        fail("descriptor fields are invalid")
    if data["scope"] not in (["piv", "otp"], ["piv", "otp", "fido2"]):
        fail("scope is invalid")
    if not isinstance(data["serial"], int) or data["serial"] <= 0:
        fail("serial is invalid")
    if data["management_algorithm"] not in {"TDES", "AES256"}:
        fail("management algorithm is invalid")
    expected_key_chars = 48 if data["management_algorithm"] == "TDES" else 64
    if not isinstance(data["management_key"], str) or len(data["management_key"]) != expected_key_chars:
        fail("management key length is invalid")
    if not isinstance(data["pin"], str) or len(data["pin"]) != 8 or not data["pin"].isdigit():
        fail("PIV PIN is invalid")
    if not isinstance(data["puk"], str) or len(data["puk"]) != 8 or not data["puk"].isalnum():
        fail("PIV PUK is invalid")
    if data["derivation_profile"] not in {"v2", "legacy-v1"}:
        fail("derivation profile is invalid")
    if not isinstance(data["fido_pin"], str) or len(data["fido_pin"]) != 8 or not data["fido_pin"].isdigit():
        fail("FIDO PIN is invalid")
    for slot_number in (1, 2):
        slot = data[f"slot{slot_number}"]
        if not isinstance(slot, dict) or slot.get("kind") not in {"yubiotp", "static"}:
            fail(f"slot {slot_number} descriptor is invalid")
        if slot["kind"] == "static":
            if set(slot) != {"kind", "password"} or not isinstance(slot["password"], str):
                fail(f"slot {slot_number} static descriptor is invalid")
            if not 1 <= len(slot["password"]) <= 38 or not slot["password"].isascii():
                fail(f"slot {slot_number} static password is not valid US-layout ASCII")
        else:
            if set(slot) != {"kind", "aes_key", "private_id"}:
                fail(f"slot {slot_number} YubiOTP descriptor is invalid")
            if len(slot["aes_key"]) != 32 or len(slot["private_id"]) != 12:
                fail(f"slot {slot_number} YubiOTP key length is invalid")
    return data


def api_context(data: dict):
    package_version = tuple(int(x) for x in version("yubikey-manager").split(".")[:3])
    if not (package_version >= (5, 9, 2) and package_version < (6, 0, 0)):
        fail("yubikey-manager Python package 5.9.2 through 5.x is required")
    from ykman.device import list_all_devices
    matches = [(device, info) for device, info in list_all_devices() if info.serial == data["serial"]]
    if len(matches) != 1:
        fail("target device selection is not unique")
    return matches[0][0]


def run_phase(data: dict, phase: str) -> None:
    device = api_context(data)
    if phase == "preflight":
        return
    if phase == "piv":
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, PivSession
        algorithm = MANAGEMENT_KEY_TYPE[data["management_algorithm"]]
        with device.open_connection(SmartCardConnection) as connection:
            session = PivSession(connection)
            session.authenticate(DEFAULT_MANAGEMENT_KEY)
            session.set_management_key(algorithm, bytes.fromhex(data["management_key"]))
            session.change_puk("12345678", data["puk"])
            session.change_pin("123456", data["pin"])
            if session.get_management_key_metadata().default_value:
                fail("PIV management-key postcondition failed")
            if session.get_pin_metadata().default_value or session.get_puk_metadata().default_value:
                fail("PIV PIN/PUK postcondition failed")
        return
    if phase == "otp":
        from ykman.scancodes import KEYBOARD_LAYOUT, encode
        from yubikit.core.otp import OtpConnection
        from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession, YubiOtpSlotConfiguration
        with device.open_connection(OtpConnection) as connection:
            session = YubiOtpSession(connection)
            public_id = b"\xff\x00" + struct.pack(">I", data["serial"])
            for slot_number in (1, 2):
                slot = data[f"slot{slot_number}"]
                if slot["kind"] == "yubiotp":
                    config = YubiOtpSlotConfiguration(
                        public_id, bytes.fromhex(slot["private_id"]), bytes.fromhex(slot["aes_key"])
                    )
                else:
                    config = StaticPasswordSlotConfiguration(encode(slot["password"], KEYBOARD_LAYOUT.US))
                session.put_configuration(SLOT(slot_number), config)
            state = session.get_config_state()
            if not state.is_configured(SLOT.ONE) or not state.is_configured(SLOT.TWO):
                fail("OTP slot postcondition failed")
        return
    if phase == "fido2":
        if "fido2" not in data["scope"]:
            fail("FIDO2 is outside the requested scope")
        from fido2.ctap import CtapError
        from fido2.ctap2 import Ctap2, ClientPin
        from yubikit.core.fido import FidoConnection
        with device.open_connection(FidoConnection) as connection:
            ctap2 = Ctap2(connection)
            try:
                ClientPin(ctap2).set_pin(data["fido_pin"])
            except CtapError as error:
                if error.code in {CtapError.ERR.INVALID_LENGTH, CtapError.ERR.PIN_POLICY_VIOLATION}:
                    fail("FIDO PIN rejected by device policy")
                fail("FIDO PIN mutation failed")
            if not ctap2.info.options.get("clientPin"):
                fail("FIDO PIN postcondition failed")
        return
    fail("unsupported phase")


def main() -> None:
    phase = "validate"
    for argument in sys.argv[1:]:
        if argument.startswith("--phase="):
            phase = argument.split("=", 1)[1]
        elif argument != "--validate-only":
            fail("unsupported adapter argument")
    try:
        descriptor = validate(json.load(sys.stdin))
        if "--validate-only" not in sys.argv[1:]:
            run_phase(descriptor, phase)
    except SystemExit:
        raise
    except Exception as error:
        fail(f"phase failed: {type(error).__name__}")
    print(json.dumps({"ok": True, "phase": phase}))


if __name__ == "__main__":
    main()
