import re
import attr
import jinja2
import builtins
import enum
from typing import List, Union
import litmoose_ll as ll


@attr.dataclass
class Mem:
    loc: str

    def to_ll(self, labels=[]):
        if self.loc in labels:
            return ll.Label(self.loc)
        return ll.Mem(self.loc)


@attr.dataclass(frozen=True, repr=False)
class Register:
    register: int
    processor: int = None
    size: int = attr.ib(default=64, hash=False, cmp=False)

    def to_ll(self, platform, proc=None):
        if proc is None:
            proc = self.processor
        return ll.Register(platform, proc, self.register, self.size)

    def __repr__(self):
        return "{}:{}({})".format(
            self.processor, ("X" if self.size == 64 else "W"), self.register
        )


def X(register, processor):
    return Register(register, processor, 64)


def W(register, processor):
    return Register(register, processor, 32)


class RegisterValueType(enum.Enum):
    INTEGER = 0
    MEM = 1
    INITIAL = 2
    LABEL = 2


@attr.dataclass
class RegisterState:
    register: Register
    value_type: RegisterValueType
    value: Union[int, Mem]

    def _value_to_ll(self, labels=[]):
        if isinstance(self.value, (int, str)):
            return self.value
        return self.value.to_ll(labels)

    def to_ll(self, platform, proc, plabels):
        return ll.RegisterState(
            register=self.register.to_ll(platform, proc),
            value=self._value_to_ll(plabels),
        )

    def to_ll_inp(self, platform, proc, outs, plabels):
        return ll.RegisterInputState(
            register=self.register.to_ll(platform, proc),
            value=self._value_to_ll(plabels),
            output=self.register in outs,
        )


@attr.dataclass
class MemState:
    mem: Mem
    value: int

    def to_ll(self):
        return {self.mem.to_ll(): self.value}


@attr.dataclass
class State:
    registers: List[RegisterState]

    def to_ll(self, platform, plabels):
        ll_rs = [
            ll.RegisterState(rs.register.to_ll(platform), rs._value_to_ll(plabels))
            for rs in self.registers
        ]
        return ll.PostState(ll_rs)


@attr.dataclass
class Chunk:
    tag: str
    code: str

    def to_ll(self, platform, process, outs, plabels):
        clobbers = [
            r.to_ll(platform, process.name) for r in self.clobbers(process, outs)
        ]
        in_regs = [
            rs.to_ll_inp(platform, process.name, outs, plabels)
            for rs in self.in_registers(process)
        ]
        out_regs = [
            r.to_ll(platform, process.name) for r in self.out_registers(process, outs)
        ]
        return ll.Chunk(self.tag, self.code, clobbers, in_regs, out_regs, "UNKNOWN")

    def clobbers(self, process, outs):
        matches = re.findall(r"(x|w|r)(\d+)", self.code, re.IGNORECASE)
        named_regs = []
        for (t, n) in matches:
            if t == "x" or t == "r":
                named_regs.append(X(int(n), process.name))
            else:
                named_regs.append(W(int(n), process.name))
        in_states = process.pre.registers
        in_regs = {rs.register for rs in in_states}
        out_regs = {r for r in outs if r.processor == process.name}
        return in_regs | out_regs | set(named_regs)

    def in_registers(self, process):
        return [rs for rs in process.pre.registers]

    def out_registers(self, process, outs):
        out_regs = {r for r in outs if r.processor == process.name}
        return out_regs


curr_tag = 0


def fresh_tag():
    global curr_tag
    curr_tag += 1
    return "fresh{}".format(curr_tag)


def fresh_label():
    return ".{}".format(fresh_tag())


@attr.dataclass
class Process:
    name: int
    pre: State
    code: str
    labels: List[str]

    @property
    def chunks(self):
        cd = self.code.splitlines()
        chunk = ""
        for line in cd:
            lbl, _, _ = line.rpartition(":")
            lbl = lbl.strip()
            if lbl and " " not in lbl:
                yield Chunk(fresh_tag(), chunk)
                chunk = ""
            chunk += line + "\n"
        yield Chunk(fresh_tag(), chunk)

    def to_ll(self, platform, outs, all_labels):
        chunks = [c.to_ll(platform, self, outs, all_labels) for c in self.chunks]
        hanging_label = fresh_tag()
        for (c, cn) in zip(chunks, chunks[1:]):
            c.next = cn.tag
        if len(chunks) > 1:
            cn.next = hanging_label
        else:
            chunks[0].next = hanging_label
        return ll.Process(self.name, chunks, self.labels, hanging_label)


@attr.dataclass
class Litmus:
    pre: List[MemState]
    processes: List[Process]
    post: State
    src: str
    name: str
    platform: str
    all_labels: List[str]
    tags: List[str] = attr.Factory(list)

    def to_ll(self, platform=None):
        if platform is None:
            platform = self.platform
        outs = [rs.register for rs in self.post.registers]
        ll_procs = [p.to_ll(platform, outs, self.all_labels) for p in self.processes]
        ll_mems = {}
        for ms in self.pre:
            ll_mems.update(ms.to_ll())
        ll_post = self.post.to_ll(platform, [])
        ll_outs = [r.to_ll(platform) for r in outs]
        if platform == "aarch64":
            platform = ll.ARMv8
        elif platform == "ppc":
            platform = ll.PPC
        else:
            raise ValueError('Unknown Platform "{}"'.format(platform))
        return ll.Litmus(ll_mems, ll_procs, ll_outs, ll_post, platform)


class Parser:
    def __init__(self):
        self.platform = None

    def parse_reg(self, reg, implicit_process=None):
        p, colon, reg = reg.rpartition(":")
        if p:
            p = int(p)
        else:
            p = implicit_process

        if reg[0] == "w":
            return W(int(reg[1:]), processor=p)
        elif reg[0] == "x":
            return X(int(reg[1:]), processor=p)
        elif reg[0] == "r":
            return X(int(reg[1:]), processor=p)

        raise ValueError(reg)

    def parse_mem(self, m):
        m = re.match("mem\[(?P<mem_ref>.+)\]", m)
        if m is None:
            return None
        return Mem(m["mem_ref"])

    def parse_mem_ref(self, m):
        return Mem(m)

    def parse_value(self, v):
        if v.startswith('"'):
            _, _, t = v.partition('"')
            op, _, _ = t.partition('"')
            if op == "nop":
                if self.platform == "aarch64":
                    return RegisterValueType.INTEGER, 3_573_751_839  # NOP
                elif self.platform == "ppc":
                    return RegisterValueType.INTEGER, t0x60000000
            elif op == "nop2":
                if self.platform == "aarch64":
                    return (
                        RegisterValueType.INTEGER,
                        0b11010101000000110010_0000110_11111,
                    )
                elif self.platform == "ppc":
                    raise ValueError("Cannot generate NOP2 for PPC")
            elif op == "nop3":
                if self.platform == "aarch64":
                    return (
                        RegisterValueType.INTEGER,
                        0b11010101000000110010_0000111_11111,
                    )
                elif self.platform == "ppc":
                    raise ValueError("Cannot generate NOP3 for PPC")

            raise ValueError("Unknown opcode: {}".format(op))
        try:
            if v.startswith("0x"):
                return RegisterValueType.INTEGER, int(v, 16)
            if v.startswith("0b"):
                return RegisterValueType.INTEGER, int(v, 2)
            if v.startswith("0o"):
                return RegisterValueType.INTEGER, int(v, 8)
            return RegisterValueType.INTEGER, int(v)
        except ValueError:
            # assume mem
            return RegisterValueType.MEM, self.parse_mem_ref(v)

    def parse_state(self, state, implicit_process=None):
        regs = []
        if state:
            groups = state.split(",")
            pairs = [g.split("=") for g in groups]
            for (reg, value) in pairs:
                reg = reg.strip()
                value = value.strip()
                s = re.fullmatch(r"Initial\[(?P<loc>.+)\]", value)
                if s:
                    regs.append(
                        RegisterState(
                            self.parse_reg(reg, implicit_process=implicit_process),
                            RegisterValueType.INITIAL,
                            s.group("loc"),
                        )
                    )
                else:
                    ty, val = self.parse_value(value)
                    regs.append(
                        RegisterState(
                            self.parse_reg(reg, implicit_process=implicit_process),
                            ty,
                            val,
                        )
                    )
        return State(regs)

    def parse_mem_state(self, state):
        if not state:
            return []

        groups = state.split(",")
        pairs = [g.split("=") for g in groups]
        mems = []
        for (mem, value) in pairs:
            mem = mem.strip()
            value = value.strip()
            m = self.parse_mem(mem)
            if m is None:
                m = self.parse_mem_ref(mem)
            mems.append(MemState(m, int(value)))
        return mems

    def find_labels(self, code):
        for line in code.splitlines():
            lbl, _, _ = line.rpartition(":")
            if lbl and " " not in lbl.strip():
                yield lbl.strip()

    def parse_process(self, name, pre, code):
        return Process(
            int(name),
            self.parse_state(pre, implicit_process=int(name)),
            code.strip(),
            list(self.find_labels(code)),
        )

    def parse(self, s, litmus_name="N/A"):
        s = s.casefold()  # hacky.
        ss = ""
        for line in s.splitlines():
            sw = line.lstrip()
            if sw.startswith("//") or sw.startswith("#"):
                continue
            line, _, _ = line.partition("//")
            ss += line + "\n"
        original = s
        s = ss

        PLATFORM = r"^platform (?P<platform>.+)$\n"
        platform = re.search(PLATFORM, s, re.MULTILINE)
        if platform:
            platform = platform["platform"]
        else:
            platform = "aarch64"
        self.platform = platform

        INIT = r"^initial {(?P<init>.+)}$\n"
        # this is broken but we lookup via regex so it doesn't matter...
        TAGS = r"^tag ([,]{0,1}[ ]*(?P<tag>.+))+$\n"
        REG = (
            r"^P(?P<name>\d+):$\n"
            r"(^{(?P<pre>.+)}$\n){0,1}"
            r"(?P<code>(^\s+.+\s*$\n)+)"
        )
        POST = r"^exists {(?P<post>.+)}$\n"
        labels = set()
        matches = re.finditer(REG, s, re.MULTILINE | re.IGNORECASE)
        procs = []
        for m in matches:
            name, pre, code = m["name"], m["pre"], m["code"]
            proc = self.parse_process(name, pre, code)
            procs.append(proc)
            labels.update(proc.labels)
        post = re.search(POST, s, re.MULTILINE)
        init = re.search(INIT, s, re.MULTILINE)
        if init:
            init = init["init"]
        tags = list(re.finditer(TAGS, s, re.MULTILINE | re.IGNORECASE))
        tags = [t["tag"] for t in tags]
        return Litmus(
            self.parse_mem_state(init),
            procs,
            self.parse_state(post["post"]),
            original.lower(),
            litmus_name,
            platform,
            labels,
            tags,
        )


def parse(s, litmus_name="N/A"):
    p = Parser()
    return p.parse(s, litmus_name)


def dumps(litmus, **kws):
    litmus_ll = litmus.to_ll()

    def shuffled(xs):
        ys = list(xs)
        import random

        random.shuffle(ys)
        return ys

    with open("litmoose_template.jinja2.c") as f:
        t = jinja2.Template(f.read())
        import sys

        return t.render(
            shuffled=shuffled, litmus=litmus_ll, ll=ll, **builtins.__dict__, **kws
        )


if __name__ == "__main__":
    with open("MP+ifetches.lm") as f:
        litmus = parse(f.read())
    # print(litmus)
    # print(litmus.to_ll())
    print(dumps(litmus))
