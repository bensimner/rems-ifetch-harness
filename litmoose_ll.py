import attr
import jinja2
from typing import List, Union, Dict

@attr.dataclass(frozen=True)
class Platform:
    name: str
    strongbar: str
    fmt_register: None

    def format_register(self, r):
        return self.fmt_register(r)

ARMv8 = Platform('aarch64',
                 'dsb sy',
                 lambda r: ('x' if r.size == 64 else 'w') + str(r.register),
        )
PPC = Platform('ppc',
               'sync',
                lambda r: 'r' + str(r.register),
        )

@attr.dataclass(frozen=True)
class Mem:
    loc: str

    @property
    def name(self):
        return 'm' + str(self.loc)

    @property
    def var(self):
        return self.name

    @property
    def type_syn(self):
        return 'int64_t* '

@attr.dataclass(frozen=True)
class Label:
    name: str

@attr.dataclass(frozen=True)
class PPCRegister:
    processor: int
    register: int
    size: int = 64

    @property
    def name(self):
        return 'r' + str(self.register)

    @property
    def var_name(self):
        return 'p{}r{}'.format(self.processor, self.register)

    @property
    def reg_var(self):
        return '%[{}]'.format(self.var_name)

    @property
    def type_syn(self):
        return ('uint{}_t'.format(self.size))

    @property
    def type_fmt(self):
        return ('lu' if self.size == 64 else 'u')

@attr.dataclass(frozen=True)
class AArch64Register:
    processor: int
    register: int
    size: int

    @property
    def name(self):
        reg_prefix = ('x' if self.size == 64 else 'w')
        return reg_prefix + str(self.register)

    @property
    def var_name(self):
        reg_prefix = ('x' if self.size == 64 else 'w')
        return 'p{}{}{}'.format(self.processor, reg_prefix, self.register)

    @property
    def reg_var(self):
        prefix = '' if self.size == 64 else 'w'
        return '%{}[{}]'.format(prefix, self.var_name)

    @property
    def type_syn(self):
        return 'uint{}_t'.format(self.size)

    @property
    def type_fmt(self):
        return ('lu' if self.size == 64 else 'u')


def Register(platform, p, r, size):
    if platform == 'aarch64':
        return AArch64Register(p, r, size)
    elif platform == 'ppc':
        return PPCRegister(p, r, size)

    raise ValueError('Register({}, {}, {}, {}): unknown Platform'.format(platform, r, p, size))


@attr.dataclass(frozen=True)
class RegisterState:
    register: Register
    value: int

    def to_switch(self):
        assert isinstance(self.value, int)
        return """
        switch (%s) {
            case (%s) :
                %s
                break;
            default :
                break;
        }
        """ % (self.register.var_name, self.value, '%s')


@attr.dataclass
class PostState:
    register_states: List[RegisterState]

    def to_switch(self):
        x = '%s'
        for rs in self.register_states:
            x = x % rs.to_switch()
        return x % 'witnesses++;'

@attr.dataclass(frozen=True)
class RegisterInputState:
    register: Register
    value: int
    output: bool = False  # whether this input register is also an output register

@attr.dataclass
class MemState:
    mem: Mem
    value: int

Code = str

@attr.dataclass
class Chunk:
    tag: str
    code: Code
    clobbers: List[Register]
    in_registers: List[RegisterInputState]
    out_registers: List[Register]
    next: str

    @property
    def mems(self):
        return [rs.value for rs in self.in_registers if isinstance(rs.value, Mem)]

    @property
    def all_registers(self):
        return set(self.out_registers) | {rs.register for rs in self.in_registers}

@attr.dataclass
class Process:
    name: int
    chunks: List[Chunk]
    labels: List[str]
    hanging_label: str

    def gcc_in_reg(self, rs):
        if rs.output:
            return '"[{0}]" ({0})'.format(rs.register.var_name)
        else:
            return '[{0}] "r" ({0})'.format(rs.register.var_name)

    def gcc_out_reg(self, r):
        return '[{0}] "=&r" ({0})'.format(r.var_name)

    @property
    def clobbers(self):
        return set(r for c in self.chunks for r in c.clobbers)

    @property
    def in_registers(self):
        return set(r for c in self.chunks for r in c.in_registers)

    @property
    def out_registers(self):
        return set(r for c in self.chunks for r in c.out_registers)

    @property
    def all_registers(self):
        return set(r for c in self.chunks for r in c.all_registers)


@attr.dataclass
class Litmus:
    initial_mem: Dict[Mem, int]
    processes: List[Process]
    out_registers: List[Register]
    post_state: PostState
    platform: Platform
