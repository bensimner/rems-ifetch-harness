#define _GNU_SOURCE
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>

#define T {{len(litmus.processes)}}

typedef struct {
    pthread_cond_t* cond;
    pthread_mutex_t* mut;
    int c;
    int val;
    int turn;
} pb_t;

pthread_mutex_t glob;
int barrier_code;

pb_t barrier;

{% for p in litmus.processes %}pthread_t p{{p.name}}_t;
void* code_block_ptr{{p.name}};
{% endfor %}
static pthread_t* pts[] = { {% for p in litmus.processes %}&p{{p.name}}_t {{ "," if not loop.last }} {% endfor %} };

static uint64_t R;
static uint64_t N;

void binit(int c, pb_t* b) {
    b->cond = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
    b->mut = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    pthread_cond_init(b->cond, NULL) ;
    pthread_mutex_init(b->mut, NULL) ;
    b->c = c;
    b->val = c;
    b->turn = 0;
}

void bfree(pb_t* b) {
    pthread_cond_destroy(b->cond);
    pthread_mutex_destroy(b->mut);
    free(b->mut);
    free(b->cond);
}

void bwait(pb_t* bar) {
    pthread_mutex_lock(bar->mut);
    int t = bar->turn;
    --bar->val;
    if (bar->val == 0) {
        bar->val = bar->c;
        bar->turn++;
        pthread_cond_broadcast(bar->cond);
    } else {
        do {
            pthread_cond_wait(bar->cond, bar->mut);
        }
        while (bar->turn == t);  // a cond_t wait might wake at any time, so block a la java conds
    }
    pthread_mutex_unlock(bar->mut);
}


uint64_t BLOCK_SIZE = 1L << 32L;

int randbit(void) {
    static int rn = 0;
    if (rn == 0)
        rn = rand();

    static i = 0;
    if (i < 32) {
        int k = (rn & (1 << i)) >> i;
        i++;
        return k;
    } else {
        i = 0;
        rn = rand();
        return randbit();
    }
}



void trace(char* s) {
    //printf("{\"trace\": \"%s\"}\n", s); fflush(stdout);
}

struct Result {
    {% for r in litmus.out_registers -%}
    int64_t* {{r.var_name}};
    {% endfor -%}
};

struct ResultPair {
    struct Result* result;
    int64_t count;
    int64_t validated;
};

struct Arg {
    {% for m in litmus.initial_mem %}uint64_t* {{m.var}};
    {% endfor %}

    int run;
    int stride;
    int** cpus;
    struct Result results[];
};

void print_out(void) {
    printf("%s", "!");
}

int DONE;
void* timeout(void* a) {
    int t = 0;
    while (!DONE) {
        if (t > 5000*1000 + N*R*100*1000) {
            printf("{\"error\":\"kill\"}\n");
            exit(7);
            return NULL;
        }
        usleep(10 * 1000);
        t += 10 * 1000;
    }
    return NULL;
}

void strongbar(void) {
    asm volatile (
        "{{litmus.platform.strongbar}}\n"
    : /* no outputs */
    : /* no inputs */
    : "memory"
    );
}


void set_affinity(int p) {
#ifndef NOPTHREAD
{% if opt.affinity -%}
    cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(p, &cpu);
    int r;
    if (r=pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu)) {
        errno=r;
        warn("set_affinity");
    }
{% endif -%}
#endif
}

void delay(void) {
    for (int k = 0; k < rand() % 10; k++) {
        fflush(stdout);
    }
}

{% for p in litmus.processes -%}
{% if opt.split_labels -%}
{% for c in p.chunks -%}
 __attribute__((aligned(0x4000))) void p{{p.name}}{{c.tag}}(void){
    int64_t pagesize = getpagesize();
    void* code_block_ptr = (void*)((long)(&&_chunk_code{{c.tag}}) & ~(pagesize-1));
    if(mprotect(code_block_ptr, pagesize, PROT_READ|PROT_EXEC|PROT_WRITE)) {
        err(1, "mprotect");
    }


_chunk_code{{c.tag}}:
    asm volatile (
        "b _over_chunk_code{{c.tag}}\n"
        "{{c.tag}}: nop\n"
        {% for line in c.code.splitlines() %}"{{line}}\n"{% endfor %}
        "b {{c.next}}\n"
        "_over_chunk_code{{c.tag}}: nop\n"
    );

}
{%- endfor %}
{% endif %}

void* p{{p.name}}(void* a) {
    strongbar();
    struct Arg* arg = (struct Arg* )a;

    trace("p{{p.name}}-0.0");

    {% if opt.split_labels -%}
    {% for c in p.chunks -%}
    p{{p.name}}{{c.tag}}();
    {% endfor %}
    {%- endif %}

    {% if litmus.platform.name == "aarch64" -%}
    asm ( "adr %[out], __P{{p.name}}_start\n" : [out] "=&r" (code_block_ptr{{p.name}}) : : "memory");
    //asm volatile("adr x0, {{l}}\nldr w1, [x0]\nstr w1, [%[data]]" : : [data] "r" (ldata+{{loop.index - 1}}) : "x0", "w1", "memory");
    {% elif litmus.platform.name == "ppc" -%}
    asm volatile (
        "lis %[out], __P{{p.name}}_start@highest\n\t"
        "ori %[out], %[out], __P{{p.name}}_start@higher\n\t"
        "rldicr %[out],%[out],32,31\n\t"
        "oris %[out], %[out], __P{{p.name}}_start@h\n\t"
        "ori %[out], %[out], __P{{p.name}}_start@l\n\t"
        : [out] "=&r" (code_block_ptr{{p.name}}) : : "memory");
    {% endif %}
    trace("p{{p.name}}-0.01");
    pthread_mutex_lock(&glob);
    barrier_code++;
    pthread_mutex_unlock(&glob);
    trace("p{{p.name}}-0.02");
    int64_t pagesize = getpagesize();
    void* code_block_ptr = (void*)((long)code_block_ptr{{p.name}} & ~(pagesize-1));
    trace("p{{p.name}}-0.05");
    if(mprotect(code_block_ptr, pagesize, PROT_READ|PROT_EXEC|PROT_WRITE)) {
        trace("p{{p.name}}-0.05fail");
        err(1, "mprotect");
    }

    trace("p{{p.name}}-0");

    {% if p.labels -%}
    uint32_t ldata[{{len(p.labels)}}];
    {% endif %}
    {% for l in p.labels -%}
    {% if litmus.platform.name == "aarch64" -%}
    asm volatile("adr x0, {{l}}\nldr w1, [x0]\nstr w1, [%[data]]" : : [data] "r" (ldata+{{loop.index - 1}}) : "x0", "w1", "memory");
    {% elif litmus.platform.name == "ppc" -%}
    asm volatile (
        "lis r15, {{l}}@highest\n\t"
        "ori r15, r15, {{l}}@higher\n\t"
        "rldicr r15,r15,32,31\n"
        "oris r15, r15, {{l}}@h\n\t"
        "ori r15, r15, {{l}}@l\n\t"
        "lwz r16, 0(r15)\n"
        "stw r16, 0(%[data])\n"
        : : [data] "r" (ldata+{{loop.index - 1}}) : "r15", "r16", "memory");
    {% endif %}
    {%- endfor %}

    {% if opt.prefetch -%}
    for (int k = 0; k < R; k++) {
        int kr = arg->run*R + k;
        {% for m in p.mems -%}
        if (randbit() && arg->{{m.var}}[kr] != {{litmus.initial_mem[m]}}) {
            errx(1, "global was invalid.\n");
        }
        {% endfor %}
        {% for l in p.labels -%}
        {% if litmus.platform.name == "ppc" -%}
        uint64_t laddr{{l}};
        {% endif %}
        if (randbit()) {
            uint32_t xi;
            {% if litmus.platform.name == "aarch64" -%}
            asm volatile ("adr x0, {{l}}\nldr %w[x1], [x0]\n" : [x1] "=&r" (xi) : : "x0", "x1", "memory");
            {% elif litmus.platform.name == "ppc" -%}
            asm volatile (
                "lis %[laddr], {{l}}@highest\n\t"
                "ori %[laddr], %[laddr], {{l}}@higher\n\t"
                "rldicr %[laddr],%[laddr],32,31\n"
                "oris %[laddr], %[laddr], {{l}}@h\n\t"
                "ori %[laddr], %[laddr], {{l}}@l\n\t"
                : [laddr] "=&r" (laddr{{l}}) : :
            );
            asm volatile (
                "lwz %[rout], 0(%[laddr])\n"
                : [rout] "=&r" (xi) : [laddr] "r" (laddr{{l}}) : "memory");
            {% endif %}
            if (xi != ldata[{{loop.index - 1}}])
                errx(1, "incorrect data at label {{l}} in p{{p.name}}\n");
        }
        if (randbit()) {
            {% if litmus.platform.name == "aarch64" -%}
            asm volatile ("prfm plil1keep, {{l}}\n" : : :);
            {% elif litmus.platform.name == "ppc" -%}
            // TODO: prefetch instruction for ppc for {{l}}
            asm volatile (
                "icbt 0,r0,%[laddr]\n" : : [laddr] "r" (laddr{{l}}) :
            );
            {% endif %}
        }
        {% endfor %}
    }
    {% endif %}

    {% for r in p.all_registers -%}
    {{r.type_syn}} {{r.var_name}} = 0;
    {% endfor %}

    int c=0;
    {% if opt.indirect -%}
    int stride = arg->stride;
    for (int s = stride; s > 0; s--) {
        for (int k = R-s; k >= 0; k -= stride) {
    {% else -%}
    {
        for (int k = 0; k < R; k++) {
    {% endif %}
            int kr = arg->run*R + k;
            c++;

            {% for rs in p.in_registers-%}
            {% if isinstance(rs.value, int) -%}
            {{rs.register.var_name}} = {{rs.value}};
            {% elif isinstance(rs.value, ll.Mem) -%}
            {{rs.register.var_name}} = (int64_t )&arg->{{rs.value.var}}[kr];
            {% elif isinstance(rs.value, ll.Label) -%}
            {% if litmus.platform.name == "ppc" -%}
            asm volatile (
                "lis %[rout], {{rs.value.name}}@highest\n\t"
                "ori %[rout], %[rout], {{rs.value.name}}@higher\n\t"
                "rldicr %[rout],%[rout],32,31\n"
                "oris %[rout], %[rout], {{rs.value.name}}@h\n\t"
                "ori %[rout], %[rout], {{rs.value.name}}@l\n\t"
                : [rout] "=&r" ({{rs.register.var_name}}) : :
            );
            {% elif litmus.platform.name == "aarch64" -%}
            asm ("adr %[rout], {{rs.value.name}}\n" : [rout] "=&r" ({{rs.register.var_name}}) : : );
            {% endif %}
            {%- endif %}
            {%- endfor %}
            trace("p{{p.name}}-3");
            /* Reload data at each label */
            {% for l in p.labels -%}
            {% if litmus.platform.name == "aarch64" -%}
            asm volatile (
                "adr x0, {{l}}\n"
                "ldr w1, [%[ldata]]\n"
                "str w1, [x0]\n"
                "dc cvau, x0\n"
                "dsb ish\n"
                "ic ivau, x0\n"
                "dsb ish\n"
                :
                : [ldata] "r" (ldata+{{loop.index - 1}})
                : "x0", "w1", "memory"
            );
            {% elif litmus.platform.name == "ppc" -%}
            asm volatile (
                "lis r15, {{l}}@highest\n\t"
                "ori r15, r15, {{l}}@higher\n\t"
                "rldicr r15,r15,32,31\n"
                "oris r15, r15, {{l}}@h\n\t"
                "ori r15, r15, {{l}}@l\n\t"
                "lwz r16, 0(%[ldata])\n"
                "stw r16, 0(r15)\n"
                "dcbst r0,r15\n"
                "sync\n"
                "icbi r0,r15\n"
                :
                : [ldata] "r" (ldata + {{loop.index - 1}})
                : "memory", "r15", "r16"
            );
            {% endif %}
            {% endfor %}

            {% if opt.prefetch -%}
            /* Prefetch and check */
            if (rand() % 50) {
                {% for l in p.labels %}
                if (rand() % 2) {
                    uint32_t xi;
                    {% if litmus.platform.name == "aarch64" %}
                    asm volatile ("adr x0, {{l}}\nldr %w[x1], [x0]\n" : [x1] "=&r" (xi) : : "x0", "memory");
                    {% elif litmus.platform.name == "ppc" %}
                    asm volatile (
                        "lis r15, {{l}}@highest\n\t"
                        "ori r15, r15, {{l}}@higher\n\t"
                        "rldicr r15,r15,32,31\n"
                        "oris r15, r15, {{l}}@h\n\t"
                        "ori r15, r15, {{l}}@l\n\t"
                        "lwz %[rout], 0(r15)\n"
                        : [rout] "=&r" (xi) : : "r15", "memory");
                    {% endif %}
                    if (xi != ldata[{{loop.index - 1}}]) {
                        errx(1, "loop check: incorrect data at label {{l}} in p{{p.name}}");
                    }
                }
                {% endfor %}
            }
            {% endif %}

            trace("p{{p.name}}-6");
            {% if False -%}
            {% if p.name == 0 -%}
                printf("set affinity: { {% for m in litmus.processes -%} %d {{ "," if not loop.last }} {% endfor -%} }\n", {% for m in litmus.processes -%} arg->cpus[kr][{{m.name}}] {{ "," if not loop.last }} {% endfor -%});
            {% endif -%}
            {% endif -%}
            trace("p{{p.name}}-6.1");
            if (kr % 10)
                set_affinity(arg->cpus[kr][{{p.name}}]);
            trace("p{{p.name}}-6.5");
            bwait(&barrier); // go
            delay();
            trace("p{{p.name}}-7");

        code{{p.name}}:
            asm volatile (
            {% for r in p.in_registers -%}
            {% if litmus.platform.name == "aarch64" -%}
                "mov {{r.register.name}}, {{r.register.reg_var}}\n"
            {% elif litmus.platform.name == "ppc" -%}
                "mr {{r.register.name}}, {{r.register.reg_var}}\n"
            {% endif %}
            {% endfor %}
            "__P{{p.name}}_start: nop\n"
            {% if opt.split_labels -%}
            "b {{p.chunks[0].tag}}\n"
            "{{p.hanging_label}}: nop\n"
            {% else -%}
            {% for chunk in p.chunks -%}
            {% for line in chunk.code.splitlines() -%}
                "{{line}}\n"
            {% endfor %}
            {%- endfor %}
            {% endif %}
            "__P{{p.name}}_end: nop\n"
            {% for r in p.out_registers -%}
            {% if litmus.platform.name == "aarch64" -%}"mov {{r.reg_var}}, {{r.name}}\n"{% else %}"mr {{r.reg_var}}, {{r.name}}\n"{% endif %}
            {% endfor %}
            : {% for r in p.out_registers %} {{p.gcc_out_reg(r)}} {{ "," if not loop.last }} {% endfor %}
            : {% for rs in p.in_registers %} {{p.gcc_in_reg(rs)}} {{ "," if not loop.last }} {% endfor %}
            : "cc", "memory", {% for r in p.clobbers %} "{{r.name}}" {{ "," if not loop.last }} {% endfor %}
            );
            trace("p{{p.name}}-8");
            {% for r in litmus.out_registers -%}
            {% if r.processor == p.name -%}
            {% if r.size < 64 -%}
            {{r.var_name}} = {{r.var_name}} & 0x00000000ffffffff;
            {% endif %}
            *arg->results[kr].{{r.var_name}}={{r.var_name}};
            {% endif %}
            {% endfor %}

            trace("p{{p.name}}-9");
            bwait(&barrier); // go
        {% if p.name == 0 %}
            if (kr % (N*R / 10) == 0) {
                printf(".\n"); fflush(stdout);  /* just to show it working */
            }
        {% endif %}
        }
    }
    if (c != R)
        err(1, "p{{p.name}} not enough iterations.");
    trace("p{{p.name}}-10");
    /* reload data at each label to leave in consistent state */
    {% for l in p.labels -%}
    {% if litmus.platform.name == "aarch64" -%}
    asm volatile (
        "adr x0, {{l}}\n"
        "ldr w1, [%[ldata]]\n"
        "str w1, [x0]\n"
        "dc cvau, x0\n"
        "dsb ish\n"
        "ic ivau, x0\n"
        "dsb ish\n"
        :
        : [ldata] "r" (ldata+{{loop.index - 1}})
        : "x0", "w1", "memory"
    );
    {% elif litmus.platform.name == "ppc" -%}
    asm volatile (
        "lis r15, {{l}}@highest\n\t"
        "ori r15, r15, {{l}}@higher\n\t"
        "rldicr r15,r15,32,31\n"
        "oris r15, r15, {{l}}@h\n\t"
        "ori r15, r15, {{l}}@l\n\t"
        "lwz r16, 0(%[ldata])\n"
        "stw r16, 0(r15)\n"
        "dcbst r0,r15\n"
        "sync\n"
        "icbi r0,r15\n"
        :
        : [ldata] "r" (ldata + {{loop.index - 1}})
        : "memory", "r15", "r16"
    );
    {% endif %}
    {% endfor %}
    strongbar();
    return NULL;
}
{% endfor %}

void shuffle(int size, void** arr) {
    int k;
    void* tmp;
    for (int i = 0; i < size; i++) {
        k = rand() % size;
        tmp = arr[k];
        arr[k] = arr[i];
        arr[i] = tmp;
    }
}

void ishuffle(int size, int* arr) {
    int k;
    int tmp;
    for (int i = 0; i < size; i++) {
        k = rand() % size;
        tmp = arr[k];
        arr[k] = arr[i];
        arr[i] = tmp;
    }
}


{% if opt.branch_mispredict -%}
{% for p in litmus.processes -%}
pthread_t hammer{{p.name}};
{% endfor %}
uint32_t* hammer_instr_block;

struct hammer_arg {
    int* flag;
    void** proc;
};

int64_t MOD(int64_t n, int64_t k) {
    if (n < 0)
        return (k - ((-n) % k)) % k;
    return n % k;
}

void* hammer(void* a) {
    /* to hammer the cores but also to fool branch prediction/branch target prediction somewhat
     * it's common for CPUs to have a generic branch predictor which uses only the lower n bits of the VA
     * to predict on [target/taken]. We can abuse that by placing a process with the same lower n bit address space in a different page
     * that randomly jumps about while the other threads are working...
     *
     * We do this by creating a list of jump targets, shuffling them, converting each to an instruction that jumps to that target then replacing one of them with a RET.
     * All we then need to do is BL to the first jump and we're done.
     */
/*    static count = 0;
    int Nhammer = count++; */

    struct I {
        int pos;
        struct I* next;
    };

    struct hammer_arg* arg = (struct hammer_arg* )a;
    while (1) {
        pthread_mutex_lock(&glob);
        if (barrier_code >= T) {
            pthread_mutex_unlock(&glob);
            break;
        }
        pthread_mutex_unlock(&glob);
    }

    // Now fill an 8k block with our branches
    // at instr_block+(arg->proc & 0xffffffff)
    int n = 32; // 1 << 16;
    int i;
    struct I* locs[n];
    uint64_t code_ptr = (uint64_t) *(arg->proc);
    uint64_t hammer_ptr = (uint64_t) hammer_instr_block;
    uint64_t hammer_ptr_lower = hammer_ptr & 0xffffffffL;
    int64_t code_ptr_lower = (code_ptr & 0xffffffffL);
    int64_t k_ptr = MOD(code_ptr_lower - hammer_ptr_lower, BLOCK_SIZE);
    int64_t k = k_ptr / sizeof(int32_t);

    for (i = 0; i < n; i++) {
        struct I* s = (struct I*)malloc(sizeof(struct I));
        s->pos = 0;
        s->next = NULL;
        locs[i] = s;
    }

    int m;
    while (*arg->flag) {
        m = 1 + (rand() % (n - 1));

        for (i = 1; i < m; i++) {
            locs[i - 1]->next = locs[i];
        }

        locs[m - 1]->next = locs[0];

        shuffle(m, (void**)locs);

        for (i = 0; i < m; i++) {
            locs[i]->pos = i;
        }

        for (i = 0; i < m; i++) {
            int32_t offset = locs[i]->next->pos - i;
            uint32_t signed_offset = (uint32_t)offset & 0x3ffffff;
            {% if litmus.platform.name == "aarch64" %}
            hammer_instr_block[k+i] = (5 << 26) | signed_offset;
            {% elif litmus.platform.name == "ppc" %}
//            hammer_instr_block[k+i] = (18 << (32-6)) + ((signed_offset & 0x00ffffff) << 2) + 2;
            hammer_instr_block[k+i] = 0x60000000;
            {% endif %}
        }

        {% if litmus.platform.name == "aarch64" %}
        hammer_instr_block[k+m - 1] = 3596551104;  // RET
        {% elif litmus.platform.name == "ppc" %}
        hammer_instr_block[k+m - 1] = (19 << (32-6)) + (20 << (32-11)) + (16 << 1); // BCLR 20,0,0 (/BLR)
        {% endif %}

        delay();

        for (int i = 0; i < m; i++) {
        {% if litmus.platform.name == "aarch64" %}
            asm volatile (
                    "DC CVAU, %[jumper]\n"
                    "DSB ISH\n"
                    "IC IVAU, %[jumper]\n"
                    "DSB ISH\n"
            :
            : [jumper] "r" (hammer_instr_block+k+i)
            : "memory"
            );
        {% elif litmus.platform.name == "ppc" %}
            asm volatile (
                "dcbst r0,%[jumper]\n"
                "sync\n"
                "icbi r0,%[jumper]\n"
            :
            : [jumper] "r" (hammer_instr_block+k+i)
            : "memory"

            );
        {% endif %}
        }

        asm volatile (
        {% if litmus.platform.name == "aarch64" %}
            "ISB\n"
            "BLR %[jumper]\n"
        {% elif litmus.platform.name == "ppc" %}
            "isync\n"
            "mtspr CTR, %[jumper]\n"  /* not sure if this is valid ... */
            "bcctrl 20,0,0\n"
        {% endif %}
        :
        : [jumper] "r" (hammer_instr_block+k)
        :);

        delay();
    }


    return NULL;
}
{%  endif %}

int validate_results(struct Arg* arg) {
    int witnesses = 0;
    for (int n = 0; n < R; n++) {
        {% for r in litmus.out_registers -%}
        {{r.type_syn}} {{r.var_name}} = *arg->results[n].{{r.var_name}};
        {% endfor -%}

        {% for l in litmus.all_labels -%}
        uint32_t lbl_{{l}};
        {% if litmus.platform.name == "aarch64" -%}
        asm volatile("adr x0, {{l}}\nldr %[data], [x0]\n" : [data] "=r" (lbl_{{l}}) : : "x0", "memory");
        {% elif litmus.platform.name == "ppc" -%}
        asm volatile (
            "lis r15, {{l}}@highest\n\t"
            "ori r15, r15, {{l}}@higher\n\t"
            "rldicr r15,r15,32,31\n"
            "oris r15, r15, {{l}}@h\n\t"
            "ori r15, r15, {{l}}@l\n\t"
            "lwz %[data], 0(r15)\n"
            : [data] "=r" (lbl_{{l}}) : : "r15", "memory");
        {% endif %}
        {% endfor -%}
        {{litmus.post_state.to_switch()}}
    }
    return witnesses;
}

struct Arg* mkArg(void) {
    struct Arg* arg = (struct Arg*)malloc(sizeof(struct Arg) + sizeof(struct Result[N*R]));
    int** allcpus = (int**)malloc(sizeof(int*)*N*R);
    arg->run=-1;
    arg->cpus = allcpus;
{% if opt.affinity -%}
    int nprocs = get_nprocs();
{% else %}
    int nprocs = 2;
{% endif %}
    for (int k = 0; k < N*R; k++) {
        int* cpus = (int*)malloc(sizeof(int)*T);
        int start = rand() % nprocs;
        for (int i = 0; i < T; i++) {
            int top = rand() % 2;
            if (top == 0) {
                int b = start - (start % 8);
                start = b + rand() % 8;
            }
            else {
                int b = start - (start % 8);
                start = b + 8*(rand() % nprocs) + rand() % 8;
            }
            start = (nprocs + start) % nprocs;
            cpus[i] = start;
        }
        ishuffle(T, cpus);
        allcpus[k] = cpus;

        {% for r in litmus.out_registers -%}
        arg->results[k].{{r.var_name}} = (int64_t*) malloc(sizeof(int64_t));
        {% endfor -%}
        }
    shuffle(R, (void**)allcpus);

    int stride = rand() % R;
    arg->stride = stride;

    {% for m, v in litmus.initial_mem.items() %}arg->{{m.var}} = (uint64_t*)malloc(sizeof(uint64_t)*N*R);
    for (int i = 0; i < R; i++) {
        arg->{{m.var}}[i] = {{v}};
    }
    {% endfor %}

    return arg;
}

int main(int argc,char **argv) {
    {% if opt.branch_mispredict -%}
    // allocate a 512MiB space that we will fill with our branches at the designated locations
    hammer_instr_block = (uint32_t* )mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_EXEC|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    {% endif %}
    srand(time(NULL));

    if (argc > 1)
        R = atoi(argv[1]);
    else
        R = 1;

    if (argc > 2)
        N = atoi(argv[2]);
    else
        N = 1;

    int K = {{len(litmus.out_registers)}};
    struct Arg* arg = mkArg();

    trace("main-0");
    trace("main-1");

    trace("main-2");

    binit(T, &barrier);

    trace("main-3");

    int flag = 1;
    int r;
    {% if opt.branch_mispredict -%}
    {% for p in litmus.processes -%}
    cpu_set_t hammer_cpus{{p.name}};
    struct hammer_arg hammer_arg{{p.name}};
    hammer_arg{{p.name}}.proc = &code_block_ptr{{p.name}};
    hammer_arg{{p.name}}.flag = &flag;
    pthread_create(&hammer{{p.name}}, NULL, *hammer, (void* )&hammer_arg{{p.name}});
    trace("main-4-{{p.name}}");

    CPU_ZERO(&hammer_cpus{{p.name}});
    CPU_SET(arg->cpus[0][{{p.name}}], &hammer_cpus{{p.name}});
    {% if opt.affinity -%}
    if (r=pthread_setaffinity_np(hammer{{p.name}}, sizeof(cpu_set_t), &hammer_cpus{{p.name}})) {
        errno=r;
        warn("setaffinity_hammer{{p.name}}");
    }
    {% endif -%}
    {% endfor %}
    {% endif %}

    trace("main-5");
    DONE = 0;
    pthread_t timeout_t;
    pthread_create(&timeout_t, NULL, *timeout, NULL);

    void (*fps[T]);
    
    trace("main-6");
    {% for p in litmus.processes %}fps[{{loop.index - 1}}]=p{{p.name}};
    {% endfor %}

    for (int r = 0; r < N; r++) {
        arg->run++;
        shuffle(T, (void**)fps);
        shuffle(T, (void**)pts);
        trace("main-7");
        for (int i = 0; i < T; i++) {
            pthread_create(pts[i], NULL, fps[i], (void* )arg);
        }

        trace("main-8");
        shuffle(T, (void**)pts);
        for (int i = 0; i < T; i++) {
            pthread_join(*(pts[i]), NULL);
        }
        trace("main-9");
    }

        flag = 0;
        {% if opt.branch_mispredict -%}
        {% for p in litmus.processes -%}
        pthread_join(hammer{{p.name}}, NULL);
        {% endfor %}
        {% endif %}
        trace("main-10");

    DONE = 1;
    pthread_join(timeout_t, NULL);
    trace("main-11");

    /* collect results */
    struct ResultPair count[N*R];
    int jfill = 0;
    int found = 0;
    for (int k = 0; k < N*R; k++) {
        for (int j = 0; j < jfill; j++) {
            {% for r in litmus.out_registers -%}
            if (*count[j].result->{{r.var_name}} != *arg->results[k].{{r.var_name}})
                 continue;
            {% endfor -%}

            count[j].count++;
            found = 1;
        }

        if (found == 0) {
            count[jfill].result = &(arg->results[k]);
            count[jfill].count=1;
            jfill++;
        }
        found = 0;
    }

    int witnesses = validate_results(arg);
    for (int k = 0; k < jfill; k++) {
        char* prefix = "";
        printf("{ %s {% for r in litmus.out_registers %}\"{{r.var_name}}\":%{{r.type_fmt}}{{ "," if not loop.last}}{% endfor %}} : %lu\n", prefix, {% for r in litmus.out_registers %} *count[k].result->{{r.var_name}} {{ "," if not loop.last }} {% endfor %}, count[k].count);
    }

    printf("WITNESS: %d\n", witnesses);


    trace("main-11");
    bfree(&barrier);
    trace("main-12");
    {% if opt.branch_mispredict -%}
    munmap((void*)hammer_instr_block, BLOCK_SIZE);
    {% endif %}
    trace("main-13");
    {% for m in litmus.initial_mem -%}
    free(arg->{{m.var}});
    {% endfor %}
    for (int k = 0; k < N*R; k++)
    {
        {% for r in litmus.out_registers -%}
        free(arg->results[k].{{r.var_name}});
        {% endfor -%}
    }
    trace("main-14");
    free(arg);
    return 0;
}
