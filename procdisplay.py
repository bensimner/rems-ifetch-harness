import sys
import time
import curses
import pathlib

procfs = pathlib.Path('/proc/')
cpus = {}

def get_allowed(allowed):
    bits = bin(int(allowed.replace(',',''), 16))[2:]
    if all(b == '1' for b in bits):
        return ()
    out = []
    for i, b in enumerate(reversed(bits)):
        if b == '1':
            out.append(i)
    return tuple(out)

def update():
    pids = []
    for p in procfs.iterdir():
        try:
            pid = int(p.stem)
            pids.append(p)
        except ValueError:
            continue

    sets = set()
    running = []
    for p in pids:
        taskdir = p / 'task'
        if not taskdir.exists():
            continue
        for t in taskdir.iterdir():
            status = t / 'status'
            if not status.exists():
                continue

            with status.open() as f:
                run = False
                for line in f:
                    _, _, name = line.partition('Name:')
                    if name and not 'run' in name:
                        break

                    _, _, st = line.partition('State:')
                    if st and not 'running' in st:
                        run = True

                    _, _, allowed = line.partition('Cpus_allowed:')
                    if allowed:
                        sets.add(get_allowed(allowed))
                        if run:
                            running.extend(get_allowed(allowed))

    return sets, running

def red(s):
    return '\x1b[31m\x1b[22m{}\x1b[39m\x1b[22m'.format(s)

def show(stdscr, sr, cols=30, nprocs=80, color=True):
    sets, running = sr
    cpus = {i: 'x' for cpus in sets for i in cpus}
    for i in range(nprocs):
        s = cpus.get(i, '.')
        if color and i in running:
            stdscr.addstr(i//cols, i%cols, s, curses.color_pair(1))
        else:
            stdscr.addstr(i//cols, i%cols, s)

def main(stdscr):
    curses.start_color()
    stdscr.clear()
    stdscr.nodelay(True)
    nprocs = int(sys.argv[1])
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    color = False

    while True:
        c = stdscr.getch()
        if c == ord('c'):
            color = not color
        time.sleep(0.01)
        stdscr.clear()
        show(stdscr, update(), nprocs=nprocs, color=color)
        stdscr.refresh()

curses.wrapper(main)
