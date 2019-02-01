PROCESS_SRC = """\
void* p{N}(void* a) {
    struct Arg* arg = (struct Arg* )a;

    void* code_block_ptr = &&code{N};
    unsigned int pagesize = getpagesize();
    code_block_ptr = (void*)((long)code_block_ptr & ~(pagesize-1));
    if(mprotect(code_block_ptr, 2*pagesize-1, PROT_READ|PROT_EXEC|PROT_WRITE))
        err(1, "mprotect");

    asm volatile (
        "adr x1, old_func\n"
        "str x1, [%[addr]]\n"
        : /* no outputs */
        : [addr] "r" (addr)
        : "x1"
    );

    pthread_barrier_wait(&barrier);
    int64_t {in_registers};
code{N}:
    {in_registers_init}
    strongbar();
    asm (
        {asm_code}
    : {out_registers}
    : {in_registers}
    : {clobbers}
    );

    return NULL;
}
"""

in_register="""\
x{r}\
"""

in_register_init = """\
x{r} = 0;\
"""

out_register = """\
arg->x{r}\
"""

clobber = """\
x{r}\
"""

MAIN_SRC="""\
int main(int argc,char **argv) {
    struct Arg arg;
    arg.x0 = 0;

    pthread_barrier_init(&barrier, NULL, 2);
    pthread_barrier_init(&barrier_end, NULL, 2);

    pthread_t p0_t, p1_t;

    int n_hammers = 10;
    pthread_t hammers[n_hammers];
    int flag = 1;
    int k;
    for (k=0; k < n_hammers; k++) {
        pthread_create(hammers+k, NULL, *hammer, (void* )&flag);
    }

    _RAND(pthread_create(&p0_t, NULL, *p0, (void* )&arg),
          pthread_create(&p1_t, NULL, *p1, (void* )&arg));

    int cpu0 = rand() % 4;
    int cpu1 = rand() % 4;

    cpu_set_t cpus0, cpus1;
    CPU_ZERO(&cpus0);
    CPU_ZERO(&cpus1);
    CPU_SET(cpu0, &cpus0);
    CPU_SET(cpu1, &cpus1);
    pthread_setaffinity_np(p0_t, sizeof(cpu_set_t), &cpus0);
    pthread_setaffinity_np(p1_t, sizeof(cpu_set_t), &cpus1);

    pthread_join(p0_t, NULL);
    pthread_join(p1_t, NULL);

    flag = 0;
    for (k=0; k < n_hammers; k++) {
        pthread_join(hammers[k], NULL);
    }
    pthread_barrier_destroy(&barrier);
    pthread_barrier_destroy(&barrier_end);
    printf("{x0=%d}\n", arg.x0);
    return 0;
}
"""
