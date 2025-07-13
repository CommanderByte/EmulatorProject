# tests/test_cpuid_manager.py

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from emulator.core.cpu.x86.managers.cpuid_manager import CPUIDManager, CPUIDState
from emulator.core.event.x86.event_payloads import CpuCpuidEvent
from emulator.core.event.x86.event_types import EventTypes


class MockCPU:
    def __init__(self):
        # state registration (via BaseManager) ends up here
        self.state = MockState()
        # bus for subscribe calls
        self.event_bus = MockEventBus()
        # descriptor for cpuid_leaves
        self.capabilities = SimpleNamespace(cpuid_leaves={})


class MockState:
    def __init__(self):
        self.state = None
        self.block_name = None

    def register_block(self, block_name, state):
        self.block_name = block_name
        self.state = state


class MockEventBus:
    def __init__(self):
        self.subscriptions = []

    def subscribe(self, event, callback, priority=0):
        self.subscriptions.append((event, callback, priority))


class MockUnicorn:
    def __init__(self):
        # Use simple string names for registers
        self.registers = {
            "UC_X86_REG_EAX": 0,
            "UC_X86_REG_EBX": 0,
            "UC_X86_REG_ECX": 0,
            "UC_X86_REG_EDX": 0,
        }

    def reg_read(self, name: str) -> int:
        return self.registers.get(name, 0)

    def reg_write(self, name: str, value: int):
        self.registers[name] = value


def test_init_cpuid_manager():
    cpu = MockCPU()
    manager = CPUIDManager(cpu)

    # Ensure BaseManager registered the state block
    assert cpu.state.block_name == "cpuid"
    assert isinstance(manager.state, CPUIDState)
    # Should have subscribed to the CPUID event
    assert any(ev == EventTypes.CPU_CPUID for ev, _, _ in cpu.event_bus.subscriptions)


def test_on_cpuid_handles_static_leaves():
    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {
        0: {"UC_X86_REG_EAX": 1, "UC_X86_REG_EBX": 2, "UC_X86_REG_ECX": 3, "UC_X86_REG_EDX": 4}
    }
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    # seed input leaf in UC_X86_REG_EAX
    evt = CpuCpuidEvent(uc, 0, 0)

    result = manager.on_cpuid(evt)
    assert result is True

    # verify outputs in the same string-keyed registers
    assert uc.reg_read("UC_X86_REG_EAX") == 1
    assert uc.reg_read("UC_X86_REG_EBX") == 2
    assert uc.reg_read("UC_X86_REG_ECX") == 3
    assert uc.reg_read("UC_X86_REG_EDX") == 4


def test_on_cpuid_handles_dynamic_leaves():
    def dyn(leaf, subleaf):
        return {"UC_X86_REG_EAX": leaf + subleaf, "UC_X86_REG_EBX": 0, "UC_X86_REG_ECX": 0, "UC_X86_REG_EDX": 0}

    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {0: dyn}
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    evt = CpuCpuidEvent(uc,0,5)

    assert manager.on_cpuid(evt)
    assert uc.reg_read("UC_X86_REG_EAX") == 5
    assert uc.reg_read("UC_X86_REG_EBX") == 0
    assert uc.reg_read("UC_X86_REG_ECX") == 0
    assert uc.reg_read("UC_X86_REG_EDX") == 0


def test_on_cpuid_handles_missing_leaves():
    cpu = MockCPU()
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    uc.reg_write("UC_X86_REG_EAX", 7)
    evt = CpuCpuidEvent(uc,7,0)

    result = manager.on_cpuid(evt)
    assert result is True

    assert uc.reg_read("UC_X86_REG_EAX") == 0
    assert uc.reg_read("UC_X86_REG_EBX") == 0
    assert uc.reg_read("UC_X86_REG_ECX") == 0
    assert uc.reg_read("UC_X86_REG_EDX") == 0


def test_init_subscribes_to_cpuid_event():
    cpu = MockCPU()
    manager = CPUIDManager(cpu)
    # Expect exactly one subscription to Event.CPU_CPUID
    subs = [ev for ev, _, _ in cpu.event_bus.subscriptions]
    assert subs.count(EventTypes.CPU_CPUID) == 1


@pytest.mark.parametrize("leaf,entry,expect", [
    (0, {"UC_X86_REG_EAX":1,"UC_X86_REG_EBX":2,"UC_X86_REG_ECX":3,"UC_X86_REG_EDX":4}, (1,2,3,4)),
    (9, None,               (0,0,0,0)),
])
def test_static_and_missing_leaves(leaf, entry, expect):
    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {leaf: entry} if entry is not None else {}
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    uc.reg_write("UC_X86_REG_EAX", leaf)
    evt = CpuCpuidEvent(uc,0,0)

    result = manager.on_cpuid(evt)
    assert result is True

    out = (
        uc.reg_read("UC_X86_REG_EAX"),
        uc.reg_read("UC_X86_REG_EBX"),
        uc.reg_read("UC_X86_REG_ECX"),
        uc.reg_read("UC_X86_REG_EDX"),
    )
    assert out == expect


def test_subleaf_dict_dispatch():
    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {
        4: {
            0: {"UC_X86_REG_EAX":10,"UC_X86_REG_EBX":20,"UC_X86_REG_ECX":30,"UC_X86_REG_EDX":40},
            1: {"UC_X86_REG_EAX":11,"UC_X86_REG_EBX":21,"UC_X86_REG_ECX":31,"UC_X86_REG_EDX":41},
        }
    }
    manager = CPUIDManager(cpu)

    # subleaf 0
    uc0 = MockUnicorn()
    ev0 = CpuCpuidEvent(uc0,4,0)
    manager.on_cpuid(ev0)
    assert uc0.reg_read("UC_X86_REG_EAX") == 10
    assert uc0.reg_read("UC_X86_REG_EBX") == 20

    # subleaf 1
    uc1 = MockUnicorn()
    ev1 = CpuCpuidEvent(uc1,4,1)
    manager.on_cpuid(ev1)
    assert uc1.reg_read("UC_X86_REG_EAX") == 11
    assert uc1.reg_read("UC_X86_REG_EBX") == 21

    # unknown subleaf → fallback to default dict
    uc2 = MockUnicorn()
    uc2.reg_write("UC_X86_REG_EAX", 4)
    uc2.reg_write("UC_X86_REG_ECX", 2)
    ev2 = CpuCpuidEvent(uc2,4,2)
    manager.on_cpuid(ev2)
    assert uc2.reg_read("UC_X86_REG_EAX") in (10, 11)


def test_dynamic_callable_leaf():
    def cb(leaf, subleaf):
        return {
            "UC_X86_REG_EAX": leaf * 2 + subleaf,
            "UC_X86_REG_EBX": 99,
            "UC_X86_REG_ECX": 0,
            "UC_X86_REG_EDX": 0,
        }

    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {5: cb}
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    evt = CpuCpuidEvent(uc,5,3)

    assert manager.on_cpuid(evt)
    assert uc.reg_read("UC_X86_REG_EAX") == 5*2 + 3
    assert uc.reg_read("UC_X86_REG_EBX") == 99


def test_non_dict_non_callable_leaf():
    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {3: 12345}
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    uc.reg_write("UC_X86_REG_EAX", 3)
    uc.reg_write("UC_X86_REG_ECX", 0)
    evt = CpuCpuidEvent(uc,3,0)

    assert manager.on_cpuid(evt)
    assert all(uc.reg_read(r) == 0 for r in ("UC_X86_REG_EAX","UC_X86_REG_EBX","UC_X86_REG_ECX","UC_X86_REG_EDX"))


def test_callable_exception_returns_false_and_keeps_regs():
    def bad(leaf, subleaf):
        raise RuntimeError("fail")

    cpu = MockCPU()
    cpu.capabilities.cpuid_leaves = {2: bad}
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()
    uc.reg_write("UC_X86_REG_EAX", 2)
    uc.reg_write("UC_X86_REG_ECX", 0)
    evt = CpuCpuidEvent(uc,2,0)

    result = manager.on_cpuid(evt)
    assert result is False

    # No writes should have occurred on error
    assert uc.reg_read("UC_X86_REG_EAX") == 2
    assert uc.reg_read("UC_X86_REG_EBX") == 0
    assert uc.reg_read("UC_X86_REG_ECX") == 0
    assert uc.reg_read("UC_X86_REG_EDX") == 0


def test_on_cpuid_outer_exception_returns_false():
    """
    If any unexpected exception occurs (e.g. in reg_write),
    on_cpuid should catch it at the outer level and return False.
    """
    cpu = MockCPU()
    # static leaf so the inner logic would succeed
    cpu.capabilities.cpuid_leaves = {
        0: {
          "UC_X86_REG_EAX": 1,
          "UC_X86_REG_EBX": 2,
          "UC_X86_REG_ECX": 3,
          "UC_X86_REG_EDX": 4
        }
    }
    manager = CPUIDManager(cpu)

    uc = MockUnicorn()

    # Simulate a failure deep in reg_write
    original_write = uc.reg_write
    def flaky_reg_write(name, value):
        if name == "UC_X86_REG_EAX":
            raise RuntimeError("bus error")
        return original_write(name, value)
    uc.reg_write = flaky_reg_write

    evt = CpuCpuidEvent(uc,0,0)

    # This should be caught by the outer except → returns False
    result = manager.on_cpuid(evt)
    assert result is False