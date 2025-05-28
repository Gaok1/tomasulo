
#include <stdio.h>
#include <stdbool.h>

#define N_INSTR   8
#define RS_SIZE   4
#define ROB_SIZE  4
#define REG_SIZE  8

// Tipos de operação
typedef enum { ADD, SUB, MUL, DIV, LI, HALT } Op;

// Instrução simples: rd, rs, rt/imm
typedef struct {
    Op op;
    int rd;
    int rs;
    int rt;
} Instr;

// Programa de exemplo (sem decodificação de texto)
Instr program[N_INSTR] = {
    { LI, 1, 0, 10 },   // r1 = 10
    { LI, 2, 0, 20 },   // r2 = 20
    { ADD, 3, 1, 2 },   // r3 = r1 + r2
    { MUL, 4, 3, 2 },   // r4 = r3 * r2
    { SUB, 5, 4, 1 },   // r5 = r4 - r1
    { DIV, 6, 5, 2 },   // r6 = r5 / r2
    { ADD, 7, 6, 1 },   // r7 = r6 + r1
    { HALT, 0, 0, 0 }
};

// Estações de Reserva (RS)
typedef struct {
    bool busy;
    Op op;
    int vj, vk;
    int qj, qk;
    int dst;
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

// Unidade Funcional única para simplificar o fluxo
typedef struct {
    bool busy;
    Op op;
    int vj, vk;
    int dst;
    int cycles;
} FU;
FU fu = {0};

// Registradores e controles
typedef struct {
    int regs[REG_SIZE];
    int pc;
    int rob_head;
    int rob_tail;
    int rob_count;
    int clock_cycle;
} State;

State S = {{0},0,0,0,0,0};

// Verificadores de espaço
bool rob_full() { return S.rob_count >= ROB_SIZE; }
bool rs_full()  {
    for(int i=0; i<RS_SIZE; i++)
        if(!RS[i].busy) return false;
    return true;
}

// Empurra entrada no ROB
int rob_push(Op op, int rd) {
    int idx = S.rob_tail;
    ROB[idx].busy = true;
    ROB[idx].op = op;
    ROB[idx].dstReg = rd;
    ROB[idx].ready = false;
    S.rob_tail = (S.rob_tail + 1) % ROB_SIZE;
    S.rob_count++;
    return idx;
}

// Commit da cabeça do ROB
void rob_commit() {
    ROBRow *r = &ROB[S.rob_head];
    if(r->busy && r->ready) {
        S.regs[r->dstReg] = r->value;
        printf("[Commit] r%d = %d\n", r->dstReg, r->value);
        r->busy = false;
        S.rob_head = (S.rob_head + 1) % ROB_SIZE;
        S.rob_count--;
    }
}

// Issuing de instruções
void issue() {
    if(program[S.pc].op != HALT && !rob_full() && !rs_full()) {
        Instr ins = program[S.pc++];
        int rob_idx = rob_push(ins.op, ins.rd);
        for(int i=0; i<RS_SIZE; i++) {
            if(!RS[i].busy) {
                RS[i].busy = true;
                RS[i].op   = ins.op;
                RS[i].dst  = rob_idx;
                if(ins.op == LI) {
                    RS[i].vj = ins.rt; RS[i].qj = -1;
                    RS[i].vk = 0;      RS[i].qk = -1;
                } else {
                    // operandos
                    RS[i].vj = (RS[i].qj<0) ? S.regs[ins.rs] : 0;
                    RS[i].vk = (RS[i].qk<0) ? S.regs[ins.rt] : 0;
                    RS[i].qj = (ins.rs);
                    RS[i].qk = (ins.rt);
                }
                printf("[Issue] op=%d to ROB[%d] at RS[%d]\n", ins.op, rob_idx, i);
                break;
            }
        }
    }
}

// Envia instrução pronta para FU
void execute() {
    if(!fu.busy) {
        for(int i=0; i<RS_SIZE; i++) {
            RSRow *r = &RS[i];
            if(r->busy && r->qj<0 && r->qk<0) {
                fu.busy = true;
                fu.op   = r->op;
                fu.vj   = r->vj;
                fu.vk   = r->vk;
                fu.dst  = r->dst;
                fu.cycles = 1;
                r->busy = false;
                printf("[Execute] FU recebe op=%d\n", fu.op);
                break;
            }
        }
    }
}

// Write-back dos resultados
void writeback() {
    if(fu.busy) {
        if(--fu.cycles <= 0) {
            int res = 0;
            switch(fu.op) {
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
}

// Main
int main() {
    while(1) {
        printf("\n=== Cycle %d ===\n", S.clock_cycle);
        issue();
        execute();
        writeback();
        rob_commit();

        if(program[S.pc].op==HALT && S.rob_count==0 && !fu.busy) {
            printf("Fim. Regs finais:\n");
            for(int i=0;i<REG_SIZE;i++) printf("r%d=%d ", i, S.regs[i]);
            printf("\n");
            break;
        }
        S.clock_cycle++;
    }
    return 0;
}

