#include <stdio.h>
#include <stdbool.h>

#define N_INSTR   6
#define RS_SIZE   4
#define ROB_SIZE  4
#define REG_SIZE  8

typedef enum { ADD, SUB, MUL, DIV, LI, HALT } Op;

typedef struct {
    Op op;
    int rd, rs, rt;    // para LI: usa rd e rt = imediato
} Instr;

// programa de exemplo
Instr program[N_INSTR] = {
    { LI, 1, 0, 10 },   // r1 = 10
    { LI, 2, 0, 20 },   // r2 = 20
    { ADD, 3, 1, 2 },   // r3 = r1 + r2
    { MUL, 4, 3, 2 },   // r4 = r3 * r2
    { SUB, 5, 4, 1 },   // r5 = r4 - r1
    { HALT, 0, 0, 0 }
};

// Estações de Reserva (RS)
typedef struct {
    bool busy;
    Op op;
    int vj, vk;
    int qj, qk;   // índice no ROB ou -1 se pronto
    int dst;      // posição no ROB
} RSRow;
RSRow RS[RS_SIZE];

// Reorder Buffer (ROB)
typedef struct {
    bool busy;
    Op op;
    int dstReg;
    int value;
    bool ready;
} ROBRow;
ROBRow ROB[ROB_SIZE];

// Unidade Funcional única (para simplificar)
typedef struct {
    bool busy;
    Op op;
    int vj, vk;
    int dst;      // índice no ROB
    int cycles;
} FU;
FU fu = {0};

// Registradores e ponteiros
int regs[REG_SIZE] = {0};
int pc = 0, rob_head = 0, rob_tail = 0, rob_count = 0;
int clock_cycle = 0;

// Helpers
bool rob_full()    { return rob_count >= ROB_SIZE; }
bool rs_full()     { 
    for(int i=0;i<RS_SIZE;i++) if(!RS[i].busy) return false;
    return true;
}
int  rob_push(Op op, int rd) {
    int e = rob_tail;
    ROB[e] = (ROBRow){ .busy=true, .op=op, .dstReg=rd, .ready=false };
    rob_tail = (rob_tail+1)%ROB_SIZE;
    rob_count++;
    return e;
}
void rob_commit() {
    ROBRow *r = &ROB[rob_head];
    if(r->busy && r->ready) {
        regs[r->dstReg] = r->value;
        r->busy = false;
        rob_head = (rob_head+1)%ROB_SIZE;
        rob_count--;
        printf("[Commit] r%d = %d\n", r->dstReg, regs[r->dstReg]);
    }
}

int main() {
    while (1) {
        printf("\n=== Cycle %d ===\n", clock_cycle);

        // 1) ISSUE
        if (program[pc].op != HALT && !rob_full() && !rs_full()) {
            Instr ins = program[pc++];
            int rob_idx = rob_push(ins.op, ins.rd);
            // achar RS livre
            for(int i=0;i<RS_SIZE;i++){
                if(!RS[i].busy){
                    RS[i].busy = true;
                    RS[i].op   = ins.op;
                    RS[i].dst  = rob_idx;
                    if(ins.op == LI) {
                        RS[i].vj = ins.rt; RS[i].qj = -1;
                        RS[i].vk = 0;      RS[i].qk = -1;
                    } else {
                        // fonte 1
                        RS[i].qj = (ROB[rob_head].dstReg==ins.rs && ROB[rob_head].ready)
                                    ? -1 : ins.rs;
                        RS[i].vj = (RS[i].qj<0) ? regs[ins.rs] : 0;
                        // fonte 2
                        RS[i].qk = (ROB[rob_head].dstReg==ins.rt && ROB[rob_head].ready)
                                    ? -1 : ins.rt;
                        RS[i].vk = (RS[i].qk<0) ? regs[ins.rt] : 0;
                    }
                    break;
                }
            }
            printf("[Issue] op=%d to ROB[%d]\n", ins.op, rob_idx);
        }

        // 2) EXECUTE: enviar pra FU se pronta
        if (!fu.busy) {
            for(int i=0;i<RS_SIZE;i++){
                RSRow *r = &RS[i];
                if(r->busy && r->qj<0 && r->qk<0){
                    fu = (FU){ .busy=true, .op=r->op, .vj=r->vj, .vk=r->vk, .dst=r->dst, .cycles=1 };
                    r->busy = false;
                    printf("[Execute] FU recebe op=%d\n", fu.op);
                    break;
                }
            }
        }

        // 3) WRITE-BACK
        if (fu.busy) {
            if (--fu.cycles <= 0) {
                int res = 0;
                switch(fu.op){
                    case ADD: res = fu.vj + fu.vk; break;
                    case SUB: res = fu.vj - fu.vk; break;
                    case MUL: res = fu.vj * fu.vk; break;
                    case DIV: res = (fu.vk?fu.vj/fu.vk:0); break;
                    case LI:  res = fu.vj;          break;
                    default: break;
                }
                ROB[fu.dst].value = res;
                ROB[fu.dst].ready = true;
                printf("[WB] ROB[%d] = %d\n", fu.dst, res);
                fu.busy = false;
            }
        }

        // 4) COMMIT
        rob_commit();

        // STOP se HALT e pipeline vazio
        if (program[pc].op==HALT && rob_count==0 && !fu.busy) {
            printf("Fim: registradores finais:\n");
            for(int i=0;i<REG_SIZE;i++) printf("r%d=%d ", i, regs[i]);
            putchar('\n');
            break;
        }

        clock_cycle++;
    }
    return 0;
}
