#!/usr/bin/env python3
import re
import os
import sys
import attr
import json
import time
import click
import queue
import pprint
import signal
import string
import random
import asyncio
import crayons
import pathlib
import litmoose
import traceback
import threading
import subprocess
import collections
import datetime as dt

from tqdm import tqdm
from typing import List, Dict

CUR_DATE = dt.datetime.now().strftime('%Y-%m-%d.%H%M')
TRUNK_FMT = './results/{platform}/{lname}/%s-{mangle_prefix}/' % CUR_DATE
DEVICE_MAKE = {
    'sgs8': {
        'GCC': '~/ndk/bin/aarch64-linux-android-gcc',
        'GCCOPTS': '-Wall -std=gnu99 -O0 -fPIE -fPIC -DNOPTHREAD=0',
        'LINKOPTS': '-pie',
    }

}
GCC = {
    'aarch64': 'aarch64-linux-gnu-gcc',
    'ppc': 'powerpc64le-linux-gnu-gcc-7',
}
SSHS = {
    'aarch64': ['sgs8', 'h955', 'openq820', 'nexus9'],
    'ppc': ['clbom', 'clbam'],
}

@click.group()
def main():
    pass

def build_ppc(iform, *args):
    if iform == 'I':
        opcd, li, aa, lk = args
        return lk + ((aa & 0b1) << 1) + ((li & 0x00ffffff) << 2) + ((opcd & 0b11111) << (32-6))
    elif iform == 'XL':
        opcd, li, aa, lk = args
        return lk + ((aa & 0b1) << 1) + ((li & 0x00ffffff) << 2) + ((opcd & 0b11111) << (32-6))

def my_int(i):
    if 'x' in i:
        return int(i[2:], 16)

    if 'b' in i:
        return int(i[2:], 2)

    return int(i)

@main.command('build_ppc')
@click.argument('iform')
@click.argument('fields', type=my_int, nargs=-1)
def build(iform, fields):
    n = build_ppc(iform, *fields)
    print(n)
    print(hex(n))
    print(bin(n))

@main.command('unsplit')
@click.argument('N')
@click.argument('fields', nargs=-1)
@click.option('--size', nargs=1, default=32)
def unsplit(n, fields, size):
    print(bitjoin(n, *fields, sz=size))

def bitjoin(N, *fields, sz=32):
    out = []
    for field in fields:
        bitstr, _, rhs = field.partition('[')
        bitstr = bitstr.replace('_', '')
        count, _, _ = rhs.partition(']')
        if count:
            if len(bitstr) != int(count):
                print('E: field ({}) contained {} bits, expected {} bits'.format(bitstr, len(bitstr), count))
                sys.exit(1)
        out.append(bitstr)
    outbits = ''.join(out)
    bits = '0b{N:0>{sz}}'.format(N=outbits, sz=sz)
    if len(bits) > sz+2:
        spliced = bits[:sz+2] + '/' + bits[sz+2:]
        print('E: {spliced}: too many bits for {sz} bit instruction.'.format(spliced=spliced, sz=sz))
        sys.exit(1)

    i = int(outbits, base=2)
    return '{bits} : {i}'.format(bits=bits, i=i)

@main.command('split')
@click.argument('N')
@click.argument('fields', nargs=-1)
@click.option('--size', nargs=1, default=32)
def split(n, fields, size):
    print(bitsplit(n, *fields, sz=size))

def bitsplit(N, *field_lengths, sz=32):
    bits = iter('{N:0>{sz}}'.format(N=bin(int(N))[2:], sz=sz))
    out = []
    for field in field_lengths:
        size, _, namerhs = field.partition('[')
        name, _, _ = namerhs.partition(']')
        s = ''
        for _ in range(int(size)):
            s += next(bits)
        if name:
            s += '({})'.format(name)
        out.append(s)
    return '_'.join(out) + str(list(bits))

@main.command('splitctr')
@click.argument('N')
def splitctr(n):
    print(bitsplit(n, *'1[res1] 1[res0] 1[dic] 1[idc] 4[cwg] 4[erg] 4[DminLine] 2[L1Ip] 10[bits] 4[IminLine]'.split()))



def old_litmus(dir, f):
    cmd = '''\
    litmus7 -mach exynos9-8895.cfg -hexa -o {dir} {litmus} \
    '''.format(dir=dir, litmus=f)
#    _run_sp(cmd)


def find_test(platform, test_name):
    lm_path = pathlib.Path('test_families') / platform
    for shape_dir in lm_path.iterdir():
        for fp in shape_dir.iterdir():
            if fp.stem == test_name:
                with open(fp) as f:
                    return litmoose.parse(f.read(), litmus_name=lm_path.stem)
    raise ValueError('failed to find {}'.format(test_name))
    return None

def re_matches(regex, *args, **kws):
    if regex.startswith('!'):
        return not _re_matches(regex[1:], *args, **kws)
    return _re_matches(regex, *args, **kws)

def _re_matches(regex, tname, state, lms):
    if re.search(regex, tname, re.IGNORECASE):
        return True

    if re.search(regex, state, re.IGNORECASE):
        return True

    if any(re.search(regex, t, re.IGNORECASE) for t in lms[tname].tags):
        return True

    return False

@main.command('checkresults')
@click.argument('tests_fname')
@click.argument('tests-dir', default='results')
@click.option('--ls', is_flag=True)
def results(tests_fname, tests_dir, ls):
    test_dir = pathlib.Path(tests_dir)
    names = {str(f) for f in test_dir.iterdir() if f.suffix == '.lm'}
    tests = {t for (t, _) in read_tests(tests_fname)}
    from pprint import pprint as print;
    if ls:
        print(names)
    else:
        print(names - tests)


@main.command('results')
@click.argument('tests_fname')
@click.argument('tests_re', nargs=-1)
@click.option('--source', '-s', nargs=1, is_flag=True)
def results(tests_fname, tests_re, source):
    results = {}
    lms = {}
    resultsdir = pathlib.Path('results')
    expected = {}
    all_sshs = set()


    for (tname, state) in read_tests(tests_fname):
        with open(tname) as lm:
            lms[tname] = litmoose.parse(lm.read(), litmus_name=tname)

        platform = lms[tname].platform
        lm_name = pathlib.Path(tname).stem
        rdir = resultsdir / platform / lm_name

        if not all(re_matches(r, tname, state, lms=lms) for r in tests_re):
            continue

        if not rdir.exists():
            continue
        expected[tname] = state

        results[tname] = {}
        for uid in rdir.iterdir():
            for ssh in [d for d in uid.iterdir() if d.suffix == '.hist']:
                all_sshs.add(ssh.stem)
                try:
                    r = Result.from_path(ssh)
                except Exception as e:
                    print('Failed to load {}'.format(ssh))
                    continue
                if ssh.stem in results[tname]:
                    results[tname][ssh.stem] = Result.merge(results[tname][ssh.stem], r)
                else:
                    results[tname][ssh.stem] = r

    for tname, sshs in results.items():
        tqdm.write('{}: (expect {})'.format(tname, expected[tname]))
        for ssh in sorted(all_sshs):
            r = results[tname].get(ssh, Result(tname, ssh, {}, {}))
            count = sum(r.counts.values())
            validated = False
            witnesses = 0
            for (rd, c) in r.counts.items():
                obj = r.result_cache[rd]
                if lm_matches(obj, lms[tname]):
                    witnesses += c
                    validated = True
                #fmt = '{{{}: {:,}}}'.format(rd, c)
                #print('\t{}: {}'.format(ssh, fmt))
            status = get_test_status(validated, expected[tname])
            if validated:
                tqdm.write('\t{} : {}\t({:,}/{:,})'.format(ssh, status, witnesses, count))
            else:
                tqdm.write('\t{} : {}\t(0/{:,})'.format(ssh, status, count))

        if source:
            tqdm.write('')
            tqdm.write('Test:')
            tqdm.write('\n'.join('-  ' + l for l in lms[tname].src.splitlines()))
            tqdm.write('~'*80)

        print()


@main.command('run')
@click.argument('f')
@click.option('--ntimes', '-n', nargs=1, default=1)
@click.option('--nruns', '-r', nargs=1, default=1000)
@click.option('--nrepeats', '-t', nargs=1, default=1)
@click.option('--dir', nargs=1, default="temp/")
@click.option('--ssh', '-s', nargs=1, multiple=True, default=["sgs8"])
@click.option('--one-shot', is_flag=True)
@click.option('--quiet', '-q', is_flag=True)
@click.option('--forever', is_flag=True)
@click.option('--optimise', '-O', nargs=1, default=2)
def run(f, ntimes, nruns, nrepeats, dir, ssh, one_shot, quiet, forever, optimise):
    mangle = make_mangle()
    s = Settings(quiet, False, dir, one_shot)
    opt = Optimisations.from_level(optimise)
    print('Running with -O{}, enabled optimisations: {}'.format(optimise, str(opt)))
    ts = TestSettings(mangle, f, nruns, ntimes, nrepeats, '', opt)
    t = Test(ssh)
    ctx = TestContext(s, ts)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(t.build(ctx))
        loop.run_until_complete(t.run(ctx))
    except Exception as e:
        print('E:', repr(e))
        traceback.print_tb(e.__traceback__)
    finally:
        loop.run_until_complete(t.cleanup(ctx))
    loop.close()

@main.command('lm')
@click.argument('f')
def lm(f):
    from pprint import pprint as pp
    with open(f) as f:
        lm = litmoose.parse(f.read())
        print('Name:', lm.name)
        print('Platform:', lm.platform)
        print('Pre:')
        pp(lm.pre)
        print()
        for p in lm.processes:
            print('p:',p.name)
            print('Pre:')
            pp(p.pre)
            print(p.code)
            print('lbls:', p.labels)
            print()

        print('post:')
        pp(lm.post.registers)

        
        print('-'*80)
        print('LL')
        ll = lm.to_ll()
        print('platform:', ll.platform)
        print('initial_mem: ', end='')
        pp(ll.initial_mem)
        print()
        for p in ll.processes:
            print('p:', p.name)
            for c in p.chunks:
                print('in: ', end='')
                pp(c.in_registers)
                print('out: ', end='')
                pp(c.out_registers)
                print('clobber: ', end='')
                pp(c.clobbers)
                print('code:')
                print(c.code)
                print()



def read_tests(testfile):
    with open(testfile) as f:
        for line in f:
            line = line.strip()
            line, _, _ = line.partition('//')

            if line.startswith('+'):
                _, _, name = line.partition('+')
                yield from read_tests(name)
                continue
            if not line:
                continue

            words = len(line.split())
            if words == 2:
                tname, state = line.split()
            else:
                tname, _, _, state = line.split()
            yield (tname, state)

def get_test_status(validated, expected):
    if validated and expected == 'allowed':
        return crayons.green('OBSERVED')
    elif validated and expected == 'validated':
        return crayons.green('OBSERVED')
    elif validated and expected == 'forbidden?':
        return crayons.red('OBSERVED')
    elif validated and expected == 'forbidden':
        return crayons.red('OBSERVED')
    elif validated and expected == 'allowed?':
        return crayons.yellow('OBSERVED')
    elif validated and expected == 'unknown':
        return crayons.yellow('OBSERVED')

    elif not validated and expected == 'allowed':
        return crayons.cyan('UNOBSERVED')
    elif not validated and expected == 'validated':
        return crayons.blue('UNOBSERVED')
    elif not validated and expected == 'forbidden?':
        return crayons.green('UNOBSERVED')
    elif not validated and expected == 'forbidden':
        return crayons.green('UNOBSERVED')
    elif not validated and expected == 'allowed?':
        return crayons.yellow('UNOBSERVED')
    elif not validated and expected == 'unknown':
        return crayons.yellow('UNOBSERVED')

    print('Unknown get_test_status({!r}, {!r})'.format(validated, expected))

def print_test_outcome(f, test):
    tname, c, state, outcome = test
    status = get_test_status(outcome, state)
    if status:
        f.write('{} : {}/{:,}'.format(tname, status, c))
    else:
        f.write('{} : <INVALID PARAMETER>'.format(tname))


@main.command('runall')
@click.argument('tests_fname')
@click.option('--dir', nargs=1, default="temp/")
@click.option('--ssh', '-s', nargs=1, multiple=True, default=["sgs8"])
@click.option('--quiet', '-q', is_flag=True)
@click.option('--ntimes', '-n', nargs=1, type=int, default=None)
@click.option('--nruns', '-r', nargs=1, type=int, default=None)
@click.option('--nrepeats', '-t', nargs=1, type=int, default=None)
@click.option('--nworkers', '-w', nargs=1, type=int, default=4)
@click.option('--optimise', '-O', nargs=1, type=int, default=2)
def runall(tests_fname, dir, ssh, quiet, ntimes, nruns, nrepeats, nworkers, optimise):
    s = Settings(quiet, False, dir, False)
    t = Test(ssh)
    loop = asyncio.get_event_loop()

    Nd = { 'allowed': (150000, 10), 'forbidden': (550000, 10), 'forbidden?': (550000, 10), 'validated': (150000, 10)}
    def _make_test(tname, state, tests, builds, cleanup):
        r = nruns or Nd[state][0]
        n = ntimes or Nd[state][1]
        mangle = make_mangle()
        opt = Optimisations.from_level(optimise)
        ts = TestSettings(mangle, tname, r, n, nrepeats, '', opt)
        ctx = TestContext(s, ts)
        t = Test(ssh)
        builds.append(t.build(ctx))
        tests.append((tname, r*n, state, t.run(ctx, print_out=False)))
        cleanup.append(t.cleanup(ctx))

    async def worker(outcomes, q):
        while True:
            v = await q.get()
            if v is None:
                break

            tname, c, state, coro = v

            outcome = await coro
            outcomes.append((tname, c, state, outcome))

    async def filler(tests, q):
        for t in tests:
            await q.put(t)

        for _ in range(nworkers):
            await q.put(None)

    async def _run_all():
        tests = []
        builds = []
        cleanup = []
        for (tname, state) in read_tests(tests_fname):
            _make_test(tname, state, tests, builds, cleanup)
            print('test', tname)

        def cancel():
            g.cancel()

        loop.add_signal_handler(signal.SIGINT, cancel)

        try:
            # this must be sequential for now
            for g in builds:
                g = asyncio.Task(g)
                await g

            q = asyncio.Queue()
            outcomes = []
            workers = [worker(outcomes, q) for _ in range(nworkers)]
            g = asyncio.gather(filler(tests, q), *workers)
            await g
        except Exception as e:
            print('E:', repr(e))
            traceback.print_tb(e.__traceback__)
        else:
            f = SplitFile()
            for o in outcomes:
                print_test_outcome(f, o)
            f.close()
        finally:
            await asyncio.gather(*cleanup)

    loop.run_until_complete(_run_all())
    loop.close()

class SplitFile:
    def __init__(self):
        fmt = './results/all/{date}'
        date = dt.datetime.now().strftime('%Y-%m-%d')
        trunk = fmt.format(date=date)
        self.path = pathlib.Path(trunk)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(self.path, 'w')

    def write(self, m):
        self.f.write(m + '\n')
        tqdm.write(m)

    def close(self):
        self.f.close()

def make_mangle():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(2+random.choice(range(10))))

@attr.dataclass
class Optimisations:
    indirect: bool          = True
    split_labels: bool      = True
    prefetch: bool          = True
    affinity: bool          = False
    branch_mispredict: bool = True

    def __str__(self):
        fields = attr.fields(type(self))
        return '[{}]'.format(', '.join(f.name for f in fields if getattr(self, f.name)))

    @classmethod
    def from_level(cls, level):
        fields = attr.fields(cls)
        new_fields = []
        for f in fields:
            if level == 0:
                new_fields.append(False)
            elif level > 0:
                new_fields.append(True)
        return cls(*new_fields)


@attr.dataclass
class TestSettings:
    mangle: str = ""
    litmus_file: str = ""
    r: int = 1000
    n: int = 100
    t: int = 1
    platform: str = 'aarch64'
    optimisations: Optimisations = None


@attr.dataclass
class Settings:
    quiet: bool = False
    verbose: bool = False
    dir: str = 'temp/'
    once: bool = False

@attr.dataclass
class TestContext:
    settings: Settings
    test: TestSettings

@attr.dataclass
class LitmusSrc:
    litmus: litmoose.Litmus
    path: pathlib.Path

@attr.dataclass
class Test:
    sshs: List[str]
    source: LitmusSrc = None

    def generate_code(self, ctx):
        if not ctx.test.litmus_file:
            raise ValueError('Expected litmus file setting')

        path = pathlib.Path(ctx.test.litmus_file)
        with open(path) as f:
            litmus = litmoose.parse(f.read(), litmus_name=path.stem)
            self.source = LitmusSrc(litmus, path)

        ctx.test.platform = litmus.platform
        self.sshs = list(set(self.sshs) & set(SSHS[litmus.platform]))

        with open('{dir}/gen.c'.format(dir=ctx.settings.dir), 'w') as f:
            f.write(litmoose.dumps(litmus, opt=ctx.test.optimisations))

    async def build(self, ctx):
        self.generate_code(ctx)
        env = {}
        for ssh in self.sshs:
            if ssh in DEVICE_MAKE:
                env.update(DEVICE_MAKE[ssh])
                break
        else:
            env['GCC'] = GCC[ctx.test.platform]
            if ctx.test.platform == 'aarch64':
                env['EXT_GCC_OPTS'] = "-Wall"

        await Proc(['cp', 'parrun.c', '{dir}/run.c'.format(dir=ctx.settings.dir)]).run_and_wait()
        await Proc(['make']).run_and_wait(cwd=ctx.settings.dir, env=env)
        await Proc(['cp', 'run.exe', 'runpar_{ctx.test.mangle}.exe'.format(ctx=ctx)]).run_and_wait(cwd=ctx.settings.dir)

        await Proc(['cp', 'gen.c', 'run.c']).run_and_wait(cwd=ctx.settings.dir)
        await Proc(['cp', 'gen.c', '{lname}.c'.format(ctx=ctx, lname=self.source.litmus.name)]).run_and_wait(cwd=ctx.settings.dir)
        await Proc(['make']).run_and_wait(cwd=ctx.settings.dir, env=env)
        await Proc(['cp', 'run.exe', 'run_{ctx.test.mangle}.exe'.format(ctx=ctx)]).run_and_wait(cwd=ctx.settings.dir)

    async def cleanup(self, ctx):
        await Proc(['rm', 'run_{ctx.test.mangle}.exe'.format(ctx=ctx)]).run_and_wait(cwd=ctx.settings.dir, fail=False)
        await Proc(['rm', 'runpar_{ctx.test.mangle}.exe'.format(ctx=ctx)]).run_and_wait(cwd=ctx.settings.dir, fail=False)

    async def run_ssh(self, ctx, ssh_profile):
        ssh = Ssh(ssh_profile)
        tproc = TestProc(ssh, self.source)
        return (await tproc.run(ctx))

    async def run(self, ctx, print_out=True):
        #results = await asyncio.gather(*[self.run_ssh(ctx, ssh) for ssh in self.sshs], return_exceptions=True)
        results = await asyncio.gather(*[self.run_ssh(ctx, ssh) for ssh in self.sshs])

        if print_out and not ctx.settings.once:
            self.print_results(ctx, self.sshs, results)

        print([sum(r.counts.values()) for r in results])
        return self.any_validated(results)

    def print_results(self, ctx, sshs, results):
        f = File(ctx.test.mangle, self.source.litmus)

        for ssh, r in zip(sshs, results):
            self.print_result(ssh, r, file=tqdm)
            self.print_result(ssh, r, file=f)

        lm = self.source.litmus
        trunk = TRUNK_FMT.format(mangle_prefix=ctx.test.mangle, lname=lm.name, platform=lm.platform)
        path = pathlib.Path(trunk)
        tqdm.write('Results can be found in: {path}'.format(path=path/'results'))

    def print_result(self, ssh, result, file):
        file.write('*** {}'.format(ssh))
        if isinstance(result, Exception):
            file.write('    ERR: {}'.format(repr(result)))
            traceback.print_tb(result.__traceback__)
            file.write('')
            return

        validated = False
        ssh = result.ssh_profile
        total = sum(result.counts.values())
        for (objkey, c) in result.counts.items():
            obj = result.result_cache[objkey]
            if self.source is not None and lm_matches(obj, self.source.litmus):
                validated = True
            file.write('   {:,}/{:,}: {}'.format(c, total, pprint.pformat(obj)))
        if validated:
            file.write('   - {}/{:,} RESULT {}'.format(ssh, total, crayons.green('VALIDATED')))
        else:
            file.write('   - {}/{:,} RESULT {}'.format(ssh, total, crayons.red('UNOBSERVED')))

        file.write('')

    def any_validated(self, results):
        for result in results:
            if not result:
                continue

            if isinstance(result, Exception):
                continue

            for (objkey, c) in result.counts.items():
                obj = result.result_cache[objkey]
                if self.source is not None and lm_matches(obj, self.source.litmus):
                    return True
        return False


class File:
    def __init__(self, mangle_prefix, litmus_src):
        trunk = TRUNK_FMT.format(mangle_prefix=mangle_prefix, lname=litmus_src.name, platform=litmus_src.platform)
        self.path = pathlib.Path(trunk) / 'results'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(self.path, 'w')

    def write(self, m):
        self.f.write(m + '\n')

    def close(self):
        self.f.close()

def is_validated(cnter, litmus_src):
    for (count, obj) in cnter:
        if lm_matches(obj, litmus_src):
            return True
    return False

def lm_matches(obj, lm):
    if 'error' in obj:
        return False  # assume error is never intended outcome

    for rs in lm.post.registers:
        llr = rs.register.to_ll(lm.to_ll().platform.name)
        lv = rs.value
        if llr.var_name in obj:
            if obj[llr.var_name] != lv:
                return False
    return True


@attr.dataclass
class Ssh:
    ssh_profile: str

    def _run(self, cmd):
        args = ['ssh', self.ssh_profile, *cmd]
        return Proc(args)

    async def run(self, cmd):
        p = self._run(cmd)
        return (await p.run())

    async def run_and_wait(self, cmd, fail=True):
        p = self._run(cmd)
        await p.run_and_wait(fail=fail)

    async def scp(self, src, dest, fail=True):
        args = ['scp', src, dest.format(ssh=self.ssh_profile)]
        await Proc(args).run_and_wait(fail=fail)


@attr.dataclass
class Result:
    trunk_path: pathlib.Path
    ssh_profile: str
    result_cache: Dict[str, Dict[str, int]] = attr.Factory(dict)
    counts: Dict[str, int] = attr.Factory(lambda: collections.defaultdict(int))

    def blah(self):
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.trunk_path / 'Test.lm', 'w') as f:
                f.write('//')
                f.write(str(dt.datetime.now()))
                f.write('\n')
                f.write(litmus_src.src)

    def parse_line(self, line):
        # assume lines come in format `{r1: v1, r2: v2, ...} : count`
        thing, _, n = line.rpartition(':')
        if thing and thing != 'WITNESS':  # last line is a witness count
            thing_json = json.loads(thing)
            self.result_cache[str(thing_json)] = thing_json
            self.counts[str(thing_json)] += int(n)

    def dump(self):
        old = collections.defaultdict(int)
        path = self.trunk_path / (self.ssh_profile + '.hist')
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(path) as f:
                try:
                    content = json.load(f)
                    old.update(content)
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            pass

        for k, v in self.counts.items():
            old[k] += v

        with open(path, 'w') as f:
            json.dump(dict(old), f)

        self.counts = collections.defaultdict(int)

    def load(self):
        path = self.trunk_path / (self.ssh_profile + '.hist')
        with open(path) as f:
            content = json.load(f)
            self.counts.update(content)


    @classmethod
    def from_path(cls, p):
        # p ~= /dir/to/results/aarch64/Test+Name+Thing/uniqueGenId/sshProfile.hist
        p = pathlib.Path(p)
        r = Result(p, p.stem)
        with open(p) as f:
            content = json.load(f)
            r.counts = content
        cache = {}
        for k in r.counts:
            cache[k] = eval(k)
        r.result_cache = cache
        return r

    @classmethod
    def merge(cls, r1, r2):
        #assert r1.trunk_path == r2.trunk_path, 'trunks were different'
        assert r1.ssh_profile == r2.ssh_profile, 'ssh profiles were different'
        r = Result(r1.trunk_path, r1.ssh_profile)
        r.result_cache = dict(r1.result_cache)
        r.result_cache.update(r2.result_cache)
        r.counts = collections.defaultdict(int)
        for (k, c) in r1.counts.items():
            r.counts[k] += c
        for (k, c) in r2.counts.items():
            r.counts[k] += c
        return r

@attr.dataclass
class TestProc:
    ssh: Ssh
    src: LitmusSrc

    async def setup(self, ctx):
        dir = ctx.settings.dir
        await self.ssh.scp('{ctx.settings.dir}/run_{ctx.test.mangle}.exe'.format(ctx=ctx), '{{ssh}}:bjs/run_{ctx.test.mangle}.exe'.format(ctx=ctx))
        await self.ssh.scp('{ctx.settings.dir}/runpar_{ctx.test.mangle}.exe'.format(ctx=ctx), '{{ssh}}:bjs/runpar_{ctx.test.mangle}.exe'.format(ctx=ctx))
        await self.ssh.run_and_wait(['cp', 'bjs/run_{mangle}.exe'.format(mangle=ctx.test.mangle), 'bjs/run_last.exe'])

    async def cleanup(self, ctx):
        dir = ctx.settings.dir
        await self.ssh.run_and_wait(['rm', 'bjs/run_{mangle}.exe'.format(mangle=ctx.test.mangle)], fail=False)
        await self.ssh.run_and_wait(['rm', 'bjs/runpar_{mangle}.exe'.format(mangle=ctx.test.mangle)], fail=False)

    async def run(self, ctx):
        await asyncio.sleep(random.randint(0, 100) / 100)
        await self.setup(ctx)

        try:
            if ctx.settings.once:
                return (await self._run_once(ctx))
            else:
                return (await self._run(ctx))
        finally:
            await self.cleanup(ctx)

    async def _run(self, ctx):
        trunk = TRUNK_FMT.format(mangle_prefix=ctx.test.mangle,
                                 lname=self.src.litmus.name,
                                 platform=self.src.litmus.platform)

        trunk_path = pathlib.Path(trunk)
        r = Result(trunk_path, self.ssh.ssh_profile)
        for _ in range(ctx.test.t):
            await self._run_iteration(ctx, r)
        r.load()       # reload to contain all
        r.dump = None  # prevent dumping again...
        return r

    async def _run_iteration(self, ctx, r):
        p = await self.ssh.run(
            ['~/bjs/runpar_{mangle}.exe'.format(mangle=ctx.test.mangle),
             "~/bjs/run_{mangle}.exe".format(mangle=ctx.test.mangle),
             ctx.test.n,
             ctx.test.r,
            ]
        )

        async def try_read_line(msg='(unexpected end-of-stream)'):
            x = await p.stdout.readline()
            if x == b'':
                raise ValueError('EOS: {}'.format(msg))
            return x

#        assert (await try_read_line()) == b'*\n', 'did not read star'
        with tqdm(total=ctx.test.n*ctx.test.r, desc='{:>10}'.format(self.ssh.ssh_profile)) as t:
            t.bar_format = '{l_bar}{bar}| {n:,}/{total:,} [{elapsed}<{remaining}, {rate_fmt}{postfix}]'
            #c = await try_read_line()
            k = (ctx.test.r//10)

            stdout, stderr = await p.communicate()
            j = 0
            for line in stdout.decode('utf-8').splitlines():
                line = line.strip()
                if not ctx.settings.quiet:
                    print('line:', repr(line))
                if line == '.':
                    t.update(k)
                    j += 1
                else:
                    r.parse_line(line)
#            print('<{}>'.format(j))
            r.dump()

    async def _run_once(self, ctx):
        p = await self.ssh.run(['~/bjs/run_{mangle}.exe {r}; echo $?'.format(mangle=ctx.test.mangle, r=ctx.test.r)])

        lines = iter(p.stdout.readline, b'')
        while True:
            line = await p.stdout.readline()
            if line == b'':
                break

            line = line.decode('utf-8').strip()
            tqdm.write(line)

        return None

@attr.dataclass
class Proc:
    cmd: List[str]

    async def run(self, env=None, **kws):
        self.cmd = [str(c) for c in self.cmd]
        fenv = ' (env: {})'.format(env) if env else ''
        penv = {}
        penv.update(env or {})
        penv.update(os.environ)
        tqdm.write('running: {}{}'.format(' '.join(self.cmd), fenv))
        popen = await asyncio.create_subprocess_exec(
                    *self.cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=penv,
                    **kws)
        #popen = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._popen = popen
        return popen

    async def run_and_wait(self, fail=True, **kws):
        popen = await self.run(**kws)
        stdout, stderr = await popen.communicate()
        if popen.returncode:
            for line in stderr.splitlines():
                print(crayons.red(line.decode('utf-8')))
            if fail:
                raise ValueError('{} failed with exit-code {}'.format(self.cmd, popen.returncode))
            else:
                print(crayons.red('{} failed with exit-code {}'.format(self.cmd, popen.returncode)))

    @property
    def stdout(self):
        return self._popen.stdout

if __name__ == '__main__':
    main()
