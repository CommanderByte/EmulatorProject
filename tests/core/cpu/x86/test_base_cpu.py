# tests/test_base_cpu.py
from unittest.mock import Mock

import pytest
from capstone import Cs
from emulator.core.cpu.base_cpu import CPU
from emulator.core.event.event_bus import EventBus
from emulator.core.hooks.manager import HookManager
from unicorn import Uc


class TestCPU(CPU):
    def __init__(self, *args, **kwargs):
        pass

    def setup_hooks(self):
        pass

    def make_disassembler(self):
        return Mock(spec=Cs)


@pytest.fixture
def cpu():
    unicorn = Mock(spec=Uc)
    hooks = Mock(spec=HookManager)
    event_bus = Mock(spec=EventBus)
    bit_mode = 64
    return TestCPU(unicorn, hooks, event_bus, bit_mode=bit_mode)


def test_cpu_initialization(cpu):
    assert cpu.unicorn is not None
    assert cpu.hooks is not None
    assert cpu.event_bus is not None
    assert cpu.bit_mode == 64
    assert cpu._cs is not None


def test_disasm(cpu):
    mock_disasm = Mock()
    cpu._cs.disasm = mock_disasm

    code = b"\x90"
    addr = 0x1000
    cpu.disasm(code, addr)

    mock_disasm.assert_called_once_with(code, addr)


def test_subscribe(cpu):
    event = "test_event"
    handler = Mock()
    priority = 1

    cpu.subscribe(event, handler, priority)

    cpu.event_bus.subscribe.assert_called_once_with(event, handler, priority)


def test_publish(cpu):
    event = "test_event"
    args = (1, 2, 3)
    kwargs = {"key": "value"}

    cpu.event_bus.publish.return_value = ["result"]

    result = cpu.publish(event, *args, **kwargs)

    cpu.event_bus.publish.assert_called_once_with(event, *args, **kwargs)
    assert result == ["result"]
