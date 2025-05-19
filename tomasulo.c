#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define UF_MAX_ARITH 2
#define UF_MAX_MUL 1
#define UF_MAX_DIV 1

typedef int Entry;
typedef int RegAddr;

/* trecho do codigo result.h */
typedef enum
{
    RESULT_OK = 0,
    RESULT_INVALID_INPUT,
    RESULT_FILE_NOT_FOUND,
    RESULT_PARSE_ERROR,
    RESULT_UNEXPECTED,
} ResultCode;

#define INSTRUCTIONS_FILE "instructions.txt"

typedef enum Operation
{
    ADD,
    SUB,
    DIV,
    MUL,
    LI,
    HALT,
} Operation;

typedef struct Instruction
{
    Operation op;
    int regs[3]; // [0]=rd, [1]=rs or imm, [2]=rt or unused
} Instruction;

typedef struct ReserveStationRow
{
    bool busy;
    Operation op;
    int vj, vk;
    int qj, qk;
    Entry dest;
    int A;
} ReserveStationRow;

typedef struct ReserverStation
{
    int size;
    int busyLen;
    ReserveStationRow *rows;
} ReserverStation;

typedef struct
{
    Entry entry;
    int value;
} Broadcast;

typedef struct InstructionQueue
{
    Instruction *instructions;
    int size;
    int dispatchHead;
    Instruction *(*dispatch)(struct InstructionQueue *);
} InstructionQueue;

typedef struct UFTask
{
    bool active;
    ReserveStationRow row;
    int remaining;
} UFTask;

typedef struct FunctionalUnit
{
    UFTask arith_units[UF_MAX_ARITH];
    UFTask mul_units[UF_MAX_MUL];
    UFTask div_units[UF_MAX_DIV];
    bool (*instruction_buffer_available)(struct FunctionalUnit *, Operation);
    bool (*push)(struct FunctionalUnit *, ReserveStationRow);
    Broadcast *(*broadcast)(struct FunctionalUnit *);
} FunctionalUnit;

static inline void PANIC(const char *msg)
{
    fprintf(stderr, "PANIC: %s\n", msg);
    exit(EXIT_FAILURE);
}

static inline void log_mssg(const char *msg)
{
    printf("LOG: %s\n", msg);
    fflush(stdout);
}

/* trecho do codigo config.h */
#define CONFIG_FILE "config.txt"
#define CPI_DEFAULT 5

typedef enum Operation Operation; // adiantamento

typedef struct Config
{
    int mul_cpi;
    int add_cpi;
    int sub_cpi;
    int div_cpi;
    int (*get_latency)(Operation op);
} Config;

static Config *global_config = NULL;

static int config_get_latency(Operation op)
{
    switch (op)
    {
    case ADD:
    case SUB:
        return global_config->add_cpi;
    case MUL:
        return global_config->mul_cpi;
    case DIV:
        return global_config->div_cpi;
    case LI:
        return 1;
    case HALT:
    default:
        return 0;
    }
}

void pub_start_config()
{
    FILE *fp = fopen(CONFIG_FILE, "r");
    Config *cfg = malloc(sizeof *cfg);
    if (!cfg)
    {
        fprintf(stderr, "Erro em alocação para Config\n");
        exit(EXIT_FAILURE);
    }
    cfg->mul_cpi = CPI_DEFAULT;
    cfg->add_cpi = CPI_DEFAULT;
    cfg->sub_cpi = CPI_DEFAULT;
    cfg->div_cpi = CPI_DEFAULT;
    cfg->get_latency = config_get_latency;
    if (!fp)
    {
        printf("Aviso: não encontrou %s, usando defaults\n", CONFIG_FILE);
    }
    else
    {
        char line[128];
        while (fgets(line, sizeof line, fp))
        {
            if (strncmp(line, "end", 3) == 0)
                break;
            char key[16];
            int value;
            if (sscanf(line, " %15[^: ] : %d", key, &value) == 2)
            {
                if (strcmp(key, "CPI.M") == 0)
                    cfg->mul_cpi = value;
                else if (strcmp(key, "CPI.AR") == 0)
                    cfg->add_cpi = cfg->sub_cpi = value;
                else if (strcmp(key, "CPI.DIV") == 0)
                    cfg->div_cpi = value;
            }
        }
        fclose(fp);
    }
    global_config = cfg;
}

/* trecho do codigo instructionsDecode.h */

static int instruction_count = 0;

static int parse_instruction_line(const char *line, Instruction *out)
{
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '\0' || *line == '\n' || *line == '#')
        return 0;

    Instruction ins = {0};
    int r0, r1, r2, imm;
    const char *op_name = NULL; /* para debug */

    if (sscanf(line, "add r%d,r%d,r%d", &r0, &r1, &r2) == 3)
    {
        ins.op = ADD;
        op_name = "ADD";
        ins.regs[0] = r0;
        ins.regs[1] = r1;
        ins.regs[2] = r2;
    }
    else if (sscanf(line, "sub r%d,r%d,r%d", &r0, &r1, &r2) == 3)
    {
        ins.op = SUB;
        op_name = "SUB";
        ins.regs[0] = r0;
        ins.regs[1] = r1;
        ins.regs[2] = r2;
    }
    else if (sscanf(line, "mul r%d,r%d,r%d", &r0, &r1, &r2) == 3)
    {
        ins.op = MUL;
        op_name = "MUL";
        ins.regs[0] = r0;
        ins.regs[1] = r1;
        ins.regs[2] = r2;
    }
    else if (sscanf(line, "div r%d,r%d,r%d", &r0, &r1, &r2) == 3)
    {
        ins.op = DIV;
        op_name = "DIV";
        ins.regs[0] = r0;
        ins.regs[1] = r1;
        ins.regs[2] = r2;
    }
    else if (sscanf(line, "li r%d,%d", &r0, &imm) == 2)
    {
        ins.op = LI;
        op_name = "LI";
        ins.regs[0] = r0;
        ins.regs[1] = imm;
        ins.regs[2] = 0;
    }
    else if (strncmp(line, "halt", 4) == 0)
    {
        ins.op = HALT;
        op_name = "HALT";
    }
    else
    {
        return 0; //! linha não reconhecida 
    }

    //? ---------- DEBUG ---------- */
    if (op_name)
    {
        if (ins.op == LI)
            printf("[Decode] %-4s rd=r%d imm=%d\n",
                   op_name, ins.regs[0], ins.regs[1]);
        else if (ins.op == HALT)
            printf("[Decode] HALT\n");
        else
            printf("[Decode] %-4s rd=r%d rs=r%d rt=r%d\n",
                   op_name, ins.regs[0], ins.regs[1], ins.regs[2]);
    }
    /* --------------------------- */

    *out = ins;
    return 1;
}

static Instruction *pub_load_instructions(void)
{
    FILE *fp = fopen(INSTRUCTIONS_FILE, "r");
    if (!fp)
        PANIC("Error opening instructions file");
    int cap = 32, n = 0;
    Instruction *arr = malloc(cap * sizeof(Instruction));
    if (!arr)
        PANIC("Memory allocation failed for instructions");
    char line[128];
    while (fgets(line, sizeof line, fp))
    {
        Instruction ins;
        if (!parse_instruction_line(line, &ins))
            continue;
        if (n == cap)
        {
            cap *= 2;
            arr = realloc(arr, cap * sizeof(Instruction));
            if (!arr)
                PANIC("Memory reallocation failed for instructions");
        }
        arr[n++] = ins;
        if (ins.op == HALT)
            break;
    }
    fclose(fp);
    instruction_count = n;
    return arr;
}

int pub_get_instruction_count(void)
{
    return instruction_count;
}

/* trecho do codigo RegisterFile.h */

typedef struct RegisterStatus
{
    int value;
    Entry qi;
} RegisterStatus;

typedef struct RegisterFile
{
    RegisterStatus *registers;
    int size;
    RegisterStatus *(*get)(struct RegisterFile *, int);
    bool (*set_rob_entry)(struct RegisterFile *, int, Entry);
    bool (*commit_value)(struct RegisterFile *, int, Entry, int);
} RegisterFile;

static RegisterStatus *register_get(RegisterFile *self, int index)
{
    if (index >= self->size)
        return NULL;
    return &self->registers[index];
}
static bool register_set_rob_entry(RegisterFile *self, int index, Entry rob_entry)
{
    if (index >= self->size)
        return false;
    self->registers[index].qi = rob_entry;
    return true;
}
static bool register_commit_value(RegisterFile *self, int index, Entry rob_entry, int value)
{
    if (index >= self->size)
    {
        printf("[Error][RegFile] Index %d fora do range\n", index);
        return false;
    }
    RegisterStatus *reg = &self->registers[index];
    if (reg->qi != rob_entry)
    {
        printf("Registrador não escrito por esse ROB: entry %d != entry %d\n", reg->qi, rob_entry);
        return false;
    }

    reg->value = value;
    reg->qi = 0;
    printf("[Commit] Registrador %d atualizado com valor %d\n", index, value);
    return true;
}

static RegisterFile *pub_create_register_file(int size)
{
    RegisterFile *regFile = malloc(sizeof(RegisterFile));
    if (!regFile)
        PANIC("Erro em alocação para RegisterFile");
    regFile->size = size;
    regFile->registers = (RegisterStatus *)malloc(size * sizeof(RegisterStatus));
    if (!regFile->registers)
        PANIC("Erro em alocação para RegisterStatus");
    for (int i = 0; i < size; i++)
    {
        regFile->registers[i].value = 0;
        regFile->registers[i].qi = 0;
    }
    regFile->get = register_get;
    regFile->set_rob_entry = register_set_rob_entry;
    regFile->commit_value = register_commit_value;
    return regFile;
}

void printRegisterFile(RegisterFile *regFile)
{
    printf("[RegisterFile] ");
    for (int i = 0; i < regFile->size; i++)
    {
        RegisterStatus *reg = &regFile->registers[i];
        printf("r%d=%d ", i, reg->value);
    }
    printf("\n");
}

/* trecho do codigo InstructonQueue.h */

static Instruction *queue_dispatch(InstructionQueue *self)
{
    if (self->dispatchHead >= self->size)
        return NULL;
    return &self->instructions[self->dispatchHead++];
}

static InstructionQueue *pub_create_queue(int size, Instruction *instructions)
{
    InstructionQueue *queue = malloc(sizeof *queue);
    if (!queue)
        PANIC("Erro em alocação para InstructionQueue");
    queue->instructions = instructions;
    queue->size = size;
    queue->dispatchHead = 0;
    queue->dispatch = queue_dispatch;
    return queue;
}

/* trecho do codigo ReorderBuffer.h */
typedef enum ROBState
{
    ROB_ISSUE,
    ROB_EXECUTE,
    ROB_WRITE_RESULT,
    ROB_COMMIT,
} ROBState;

typedef struct ReorderBufferRow
{
    Entry entry;
    bool busy;
    Instruction inst;
    ROBState state;
    RegAddr destinationRegister;
    int value;
    int rs_tag;
} ReorderBufferRow;

typedef struct ReorderBuffer
{
    int size;
    int head;
    int tail;
    int count;
    ReorderBufferRow *rows;
} ReorderBuffer;

static ReorderBuffer *pub_create_reorder_buffer(int size)
{
    ReorderBuffer *rob = malloc(sizeof(ReorderBuffer));
    if (!rob)
        PANIC("Erro ao alocar ReorderBuffer");
    rob->size = size;
    rob->rows = calloc(size + 1, sizeof(ReorderBufferRow));
    if (!rob->rows)
        PANIC("Erro ao alocar linhas do ROB");
    rob->head = 1;
    rob->tail = 1;
    rob->count = 0;
    return rob;
}

Entry pub_reorder_buffer_insert(ReorderBuffer *rob, Instruction inst, int rs_tag)
{
    if (rob->count >= rob->size)
        PANIC("ROB cheio");
    Entry e = rob->tail;
    ReorderBufferRow *row = &rob->rows[e];
    row->entry = e;
    row->busy = true;
    row->inst = inst;
    row->state = ROB_ISSUE;
    row->destinationRegister = inst.regs[0];
    row->value = 0;
    row->rs_tag = rs_tag;
    rob->tail++;
    if (rob->tail > rob->size)
        rob->tail = 1;
    rob->count++;

    return e;
}

void pub_reserve_station_free(ReserverStation *self, ReserveStationRow *row)
{
    if (row->busy)
    {
        row->busy = false;
        row->qj = row->qk = 0;
        row->vj = row->vk = 0;
        row->dest = 0;
        self->busyLen--;
    }
}

static void pub_reorder_buffer_listen_broadcast(ReorderBuffer *rob, Broadcast bd, void *rs_void)
{
    ReorderBufferRow *row = &rob->rows[bd.entry];
    if (!row->busy || row->state != ROB_EXECUTE)
        return;
    row->value = bd.value;
    row->state = ROB_WRITE_RESULT;
    // libera RS
    struct ReserverStation *rs = rs_void;
    pub_reserve_station_free(rs, &rs->rows[row->rs_tag]);
}

static bool pub_reorder_buffer_is_full(ReorderBuffer *rob)
{
    return rob->count >= rob->size;
}

static bool pub_reorder_buffer_try_commit(ReorderBuffer *rob, RegisterFile *regFile)
{

    if (rob->count == 0)
    {
        printf("[Commit] ROB vazio, não há nada a ser commitado\n");
        return false;
    }
    ReorderBufferRow *row = &rob->rows[rob->head];
    if (row->state != ROB_WRITE_RESULT)
    {
        return false;
    }
    printf("[Commit] Tentativa de commit\n");
    if (row->destinationRegister != 0)
    {
        printf("[Commit] [REG-WRITE] Registrador de destino: %d\n", row->destinationRegister);
        regFile->commit_value(regFile, row->destinationRegister, row->entry, row->value);
    }
    else
    {
        PANIC("Commit inválido: não há registrador de destino");
    }
    row->busy = false;
    row->state = ROB_COMMIT;
    rob->head++;
    if (rob->head > rob->size)
        rob->head = 1;
    rob->count--;
    printf("[Commit] Commit de instrução realizado com sucesso. Novo head: %d\n", rob->head);
    return true;
}

/* trecho do codigo ReserveStation.h */

static ReserverStation *pub_create_reserve_station(int size)
{
    ReserverStation *station = malloc(sizeof *station);
    if (!station)
        PANIC("Erro em alocação para ReserveStation");
    station->size = size;
    station->busyLen = 0;
    station->rows = malloc(size * sizeof(ReserveStationRow));
    if (!station->rows)
        PANIC("Erro em alocação para ReserveStationRow");
    for (int i = 0; i < size; i++)
        station->rows[i].busy = false;
    return station;
}

static inline void handle_immediate(const Instruction *inst,
                                    ReserveStationRow *row)
{
    switch (inst->op)
    {
    /* 1-operando: LI rd, imm  ➜  vj = imm,  qj = 0;  vk/qk não usados */
    case LI:
        row->vj = inst->regs[1]; /* imediato já veio no campo regs[1] */
        row->qj = 0;
        row->vk = 0;
        row->qk = 0;
        break;

        /* Se futuramente tiver ADDI, ANDI, etc., trate cada caso aqui. */

    default:
        /* instrução não usa imediato → nada a fazer */
        break;
    }
}

static int pub_reserve_station_add_instruction(ReserverStation *self,
                                               Instruction inst,
                                               RegisterFile *regFile,
                                               ReorderBuffer *rob,
                                               Entry rob_entry)
{
    // encontra slot livre na RS
    int slot = self->size;
    for (int i = 0; i < self->size; ++i)
    {
        if (!self->rows[i].busy)
        {
            slot = i;
            break;
        }
    }
    if (slot == self->size)
    {
        PANIC("ReserveStation sem espaço");
    }

    // inicializa a linha
    ReserveStationRow *row = &self->rows[slot];
    row->busy = true;
    row->op = inst.op;
    row->dest = rob_entry;

    /*  trata operando imediato, se existir <<< */
    handle_immediate(&inst, row);
    if (inst.op == LI)
    {
        regFile->set_rob_entry(regFile, inst.regs[0], rob_entry);
        self->busyLen++;
        return slot;
    }

    // tratar fetch de registradores

    // ------- QJ / VJ -------
    RegisterStatus *rs = regFile->get(regFile, inst.regs[1]);
    if (rs->qi == 0)
    {
        // sem dependência pendente
        row->vj = rs->value;
        row->qj = 0;
    }
    else
    {
        Entry dep = rs->qi;
        ReorderBufferRow *depRow = &rob->rows[dep];
        // se já escreveu resultado, pega direto
        if (depRow->busy && depRow->state == ROB_WRITE_RESULT)
        {
            row->vj = depRow->value;
            row->qj = 0;
        }
        else
        {
            // ainda pendente, aguarda broadcast
            row->qj = dep;
        }
    }

    // ------- QK / VK -------
    RegisterStatus *rt = regFile->get(regFile, inst.regs[2]);
    if (rt->qi == 0)
    {
        row->vk = rt->value;
        row->qk = 0;
    }
    else
    {
        Entry dep = rt->qi;
        ReorderBufferRow *depRow = &rob->rows[dep];
        if (depRow->busy && depRow->state == ROB_WRITE_RESULT)
        {
            row->vk = depRow->value;
            row->qk = 0;
        }
        else
        {
            row->qk = dep;
        }
    }
    regFile->set_rob_entry(regFile, inst.regs[0], rob_entry);
    // contabiliza ocupação
    self->busyLen++;

    return slot;
}

static void pub_reserve_station_listen_broadcast(ReserverStation *self, Broadcast bd)
{
    for (int i = 0; i < self->size; i++)
    {
        ReserveStationRow *row = &self->rows[i];
        if (row->busy)
        {
            if (row->qj == bd.entry)
            {
                row->vj = bd.value;
                row->qj = 0;
            }
            if (row->qk == bd.entry)
            {
                row->vk = bd.value;
                row->qk = 0;
            }
        }
    }
}

static ReserveStationRow **pub_reserve_station_get_ready_all(ReserverStation *self, int *out_count)
{
    int cap = self->busyLen;
    ReserveStationRow **ready = malloc(cap * sizeof(ReserveStationRow *));
    int cnt = 0;
    for (int i = 0; i < self->size; i++)
    {
        ReserveStationRow *row = &self->rows[i];
        if (row->busy && row->qj == 0 && row->qk == 0) // se não tem dependência
            ready[cnt++] = row;                        // adiciona na lista
    }
    *out_count = cnt; // retorna o número de linhas prontas
    return ready;
}

static bool pub_has_free_space(ReserverStation *self)
{
    return self->busyLen < self->size;
}

/* trecho do codigo UF.h */

static bool uf_instruction_buffer_available(FunctionalUnit *self, Operation op)
{
    UFTask *buf;
    int cnt;
    switch (op)
    {
    case ADD:
    case SUB:
    case LI:
        buf = self->arith_units;
        cnt = UF_MAX_ARITH;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = UF_MAX_MUL;
        break;
    case DIV:
        buf = self->div_units;
        cnt = UF_MAX_DIV;
        break;
    default:
        return false;
    }
    for (int i = 0; i < cnt; i++)
        if (!buf[i].active)
            return true;
    return false;
}

static bool uf_push(FunctionalUnit *self, ReserveStationRow row)
{
    UFTask *buf;
    int cnt;
    switch (row.op)
    {
    case ADD:
    case SUB:
    case LI:
        buf = self->arith_units;
        cnt = UF_MAX_ARITH;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = UF_MAX_MUL;
        break;
    case DIV:
        buf = self->div_units;
        cnt = UF_MAX_DIV;
        break;
    default:
        return false;
    }
    for (int i = 0; i < cnt; i++)
    {
        if (!buf[i].active)
        {
            buf[i].active = true;
            buf[i].row = row;
            buf[i].remaining = global_config->get_latency(row.op);
            return true;
        }
    }
    return false;
}


static inline const char *op_to_str(Operation op)
{
    switch (op) {
        case ADD: return "ADD";
        case SUB: return "SUB";
        case MUL: return "MUL";
        case DIV: return "DIV";
        case LI:  return "LI";
        case HALT:return "HALT";
        default:  return "??";
    }
}


static Broadcast *uf_tick(FunctionalUnit *self)
{
    static Broadcast out;
    UFTask *groups[] = { self->arith_units, self->mul_units, self->div_units };
    int     limits[] = { UF_MAX_ARITH,      UF_MAX_MUL,      UF_MAX_DIV      };

    for (int g = 0; g < 3; ++g) {
        for (int i = 0; i < limits[g]; ++i) {
            UFTask *t = &groups[g][i];
            if (!t->active || t->remaining == 0)
                continue;

            t->remaining--;
            printf("[UF] Executando op=%s | vj=%d vk=%d | restante=%d\n",
                   op_to_str(t->row.op), t->row.vj, t->row.vk, t->remaining);

            if (t->remaining > 0) continue;

            /* terminou */
            t->active = false;
            int res = 0;
            switch (t->row.op) {
                case ADD: res = t->row.vj + t->row.vk; break;
                case SUB: res = t->row.vj - t->row.vk; break;
                case MUL: res = t->row.vj * t->row.vk; break;
                case DIV: res = (t->row.vk != 0) ? t->row.vj / t->row.vk : 0; break;
                case LI:  res = t->row.vj;            break;
                default:  break;
            }

            printf("[UF] [Broadcast] Finalizou %s | ROB=%d | Resultado=%d\n",
                   op_to_str(t->row.op), t->row.dest, res);

            out.entry = t->row.dest;
            out.value = res;
            return &out;
        }
    }
    return NULL;
}


static FunctionalUnit *pub_create_functional_unit(void)
{
    FunctionalUnit *uf = malloc(sizeof *uf);
    if (!uf)
        PANIC("Erro ao alocar FunctionalUnit");
    memset(uf->arith_units, 0, sizeof uf->arith_units);
    memset(uf->mul_units, 0, sizeof uf->mul_units);
    memset(uf->div_units, 0, sizeof uf->div_units);
    uf->instruction_buffer_available = uf_instruction_buffer_available;
    uf->push = uf_push;
    uf->broadcast = uf_tick;
    return uf;
}

static bool uf_is_idle(FunctionalUnit *uf)
{
    UFTask *all[] = {uf->arith_units, uf->mul_units, uf->div_units};
    int sz[] = {UF_MAX_ARITH, UF_MAX_MUL, UF_MAX_DIV};
    for (int g = 0; g < 3; g++)
        for (int i = 0; i < sz[g]; i++)
            if (all[g][i].active)
                return false;
    return true;
}

/* trecho do codigo main.c */

int GLOBAL_CLOCK = 0;

RegisterFile *register_file;
ReorderBuffer *reorder_buffer;
ReserverStation *reserve_station;
InstructionQueue *instruction_queue;
FunctionalUnit *functional_unit;

int main()
{
    pub_start_config();
    register_file = pub_create_register_file(32);
    reorder_buffer = pub_create_reorder_buffer(32);
    reserve_station = pub_create_reserve_station(16);
    functional_unit = pub_create_functional_unit();
    Instruction *instructions = pub_load_instructions();
    instruction_queue = pub_create_queue(pub_get_instruction_count(), instructions);

    bool halt_received = false;
    while (1)
    {
        printf(">>> CLOCK %d <<<\n", GLOBAL_CLOCK);

        // 1: Issue
        if (!halt_received && pub_has_free_space(reserve_station) && !pub_reorder_buffer_is_full(reorder_buffer))
        {
            printf("[Issue] Emissão de instrucao\n");
            Instruction *inst = instruction_queue->dispatch(instruction_queue);
            if (inst)
            {
                if (inst->op == HALT)
                {
                    halt_received = true;
                    printf("[HALT] Fim da emissao.\n");
                }
                else
                {
                    Entry entry = pub_reorder_buffer_insert(reorder_buffer, *inst, 0);
                    // marca o register file para usar esse ROB na instrução de destino
                    int rs_tag = pub_reserve_station_add_instruction(reserve_station, *inst, register_file, reorder_buffer, entry);

                    reorder_buffer->rows[entry].rs_tag = rs_tag;
                    printf("[Issue] RS.tag = %d, ROB.entry = %d\n", rs_tag, entry);
                }
            }
        }

        // 2: Execute
        int ready_count = 0;
        ReserveStationRow **ready = pub_reserve_station_get_ready_all(reserve_station, &ready_count);
        for (int i = 0; i < ready_count; i++)
        {
            ReserveStationRow *row = ready[i];
            if (functional_unit->instruction_buffer_available(functional_unit, row->op))
            {
                functional_unit->push(functional_unit, *row);
                reorder_buffer->rows[row->dest].state = ROB_EXECUTE;
                printf("[Execute] Enviado ROB.destRegister = %d\n", row->dest);
            }
        }
        free(ready);

        // 3: Write-back
        Broadcast *bd = functional_unit->broadcast(functional_unit);
        if (bd)
        {
            printf("[WriteBack] ROB.entry = %d | result => %d\n", bd->entry, bd->value);
            pub_reorder_buffer_listen_broadcast(reorder_buffer, *bd, reserve_station);
            pub_reserve_station_listen_broadcast(reserve_station, *bd);
        }

        // 4: Commit
        if (pub_reorder_buffer_try_commit(reorder_buffer, register_file))
        {
            int e = reorder_buffer->head == 1 ? reorder_buffer->size : reorder_buffer->head - 1;
            printf("[Commit] Entry  %d\n", e);
        }

        if (halt_received && reorder_buffer->count == 0 && reserve_station->busyLen == 0 && uf_is_idle(functional_unit))
        {
            printf("Pipeline vazio. Ciclos: %d\n", GLOBAL_CLOCK);
            break;
        }
        GLOBAL_CLOCK++;
        if (GLOBAL_CLOCK > 100)
        {
            printRegisterFile(register_file);
            printf("Pipeline não esvaziou em 100 ciclos. Abortando...\n");
            break;
        }
        puts("-----------------------------------------------------------------------------------------------------\n\n");
    }
    printRegisterFile(register_file);
    return 0;
}
