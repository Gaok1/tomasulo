
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <locale.h>

#define MUL_UF_POWER 1
#define DIV_UF_POWER 1
#define ARTH_UF_POWER 2
#define LOAD_STORE_UF_POWER 2

#define MUL_RS_ROWS 2
#define DIV_RS_ROWS 2
#define ARITH_RS_ROWS 3
#define LOAD_STORE_RS_ROWS 4

typedef int Entry;
typedef int RegAddr;

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
    LOAD,
    STORE,
    HALT,
} Operation;

typedef struct RAM
{
    double *data;
    int size;

    double (*load)(struct RAM *, int);
    void (*store)(struct RAM *, int, double);
} RAM;

typedef struct Instruction
{
    Operation op;
    int regs[3]; // [0]=rd or src (store), [1]=rs base, [2]=rt or offset(immediate)
} Instruction;

typedef struct ReserveStationRow
{
    bool busy;
    Operation op;
    double vj, vk; // operandos
    int qj, qk;    // tags das estações produtoras dos operandos
    Entry dest;    // entrada no ROB
    int A;         // imediato (offset para load/store)
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
    double value;
} Broadcast;

typedef struct InstructionQueue
{
    Instruction *instructions;
    int size;
    int dispatchHead;
    /// @brief despacha a próxima instrução da fila `remove`
    Instruction *(*dispatch)(struct InstructionQueue *);
    /// @brief retorna referencia para a próxima instrução a ser despachada `não remove`
    Instruction *(*peek)(struct InstructionQueue *);
} InstructionQueue;

typedef struct UFTask
{
    bool active;
    ReserveStationRow row;
    int remaining;
    ReserverStation *rs;
} UFTask;

typedef struct FunctionalUnit
{
    UFTask arith_units[ARTH_UF_POWER];
    UFTask mul_units[MUL_UF_POWER];
    UFTask div_units[DIV_UF_POWER];
    UFTask load_store_units[LOAD_STORE_UF_POWER];

    // Reserve stations de cada UF
    ReserverStation *arith_rs;
    ReserverStation *mul_rs;
    ReserverStation *div_rs;
    ReserverStation *load_store_rs;

    /// @brief  Verifica se há espaço no buffer de instruções da unidade funcional
    /// @param self  ponteiro para a unidade funcional
    /// @param op  operação a ser verificada
    /// @return  `true` se houver espaço, `false` caso contrário
    bool (*instruction_buffer_available)(struct FunctionalUnit *, Operation);

    /// @brief  Insere uma linha na unidade funcional
    /// @param self  ponteiro para a unidade funcional
    /// @param row  linha da RS a ser inserida
    /// @return  `true` se a inserção foi bem-sucedida, `false` caso contrário
    bool (*push)(struct FunctionalUnit *, ReserveStationRow);
    Broadcast *(*broadcast)(struct FunctionalUnit *);
    bool (*rsHasFreeSpace)(struct FunctionalUnit *, Operation);
} FunctionalUnit;

typedef struct RegisterStatus
{
    double value;
    Entry qi;
} RegisterStatus;

typedef struct RegisterFile
{
    RegisterStatus *registers;
    int size;
    RegisterStatus *(*get)(struct RegisterFile *, int);
    bool (*set_rob_entry)(struct RegisterFile *, int, Entry);
    bool (*commit_value)(struct RegisterFile *, int, Entry, double);
} RegisterFile;

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
    double value;
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

/* Funções utilitárias */

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

#define CONFIG_FILE "config.txt"
#define CPI_DEFAULT 1

typedef enum Operation Operation;

typedef struct Config
{
    int mul_cpi;
    int add_cpi;
    int sub_cpi;
    int div_cpi;
    int load_cpi;
    int store_cpi;
    int (*get_latency)(Operation op);
} Config;

/* Globals*/

static RAM global_ram;         // RAM global
int GLOBAL_CLOCK = 0;          // Clock global
RegisterFile *register_file;   // Registrador global
ReorderBuffer *reorder_buffer; // ROB global
// ReserverStation *reserve_station; // Removido, RS será específico em FunctionalUnit

InstructionQueue *instruction_queue; // Fila de instruções global
FunctionalUnit *functional_unit;     // UF global

static Config *global_config = NULL;

/* Configuraçao */

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
    case LOAD:
        return global_config->load_cpi;
    case STORE:
        return global_config->store_cpi;
    case HALT:
    default:
        return 0;
    }
}

static inline const char *op_to_str(Operation op)
{
    switch (op)
    {
    case ADD:
        return "ADD";
    case SUB:
        return "SUB";
    case MUL:
        return "MUL";
    case DIV:
        return "DIV";
    case LI:
        return "LI";
    case LOAD:
        return "LOAD";
    case STORE:
        return "STORE";
    case HALT:
        return "HALT";
    default:
        return "??";
    }
}

/**
 * @brief Le as configurações do arquivo config.txt que configura as CPI's para cada operação
 *
 *  modifica a variavel global `global_config`
 */
void pub_start_config()
{
    FILE *fp = fopen(CONFIG_FILE, "r");
    Config *cfg = malloc(sizeof *cfg);
    if (!cfg)
    {
        fprintf(stderr, "Erro em alocaçao para Config\n");
        exit(EXIT_FAILURE);
    }
    cfg->mul_cpi = CPI_DEFAULT;
    cfg->add_cpi = CPI_DEFAULT;
    cfg->sub_cpi = CPI_DEFAULT;
    cfg->div_cpi = CPI_DEFAULT;
    cfg->load_cpi = 2;  // exemplo
    cfg->store_cpi = 2; // exemplo
    cfg->get_latency = config_get_latency;
    if (!fp)
    {
        printf("Aviso: nao encontrou %s, usando defaults\n", CONFIG_FILE);
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
                if (strcmp(key, "CPI.MUL") == 0)
                    cfg->mul_cpi = value;
                else if (strcmp(key, "CPI.AR") == 0)
                    cfg->add_cpi = cfg->sub_cpi = value;
                else if (strcmp(key, "CPI.DIV") == 0)
                    cfg->div_cpi = value;
                else if (strcmp(key, "CPI.LOAD") == 0)
                    cfg->load_cpi = value;
                else if (strcmp(key, "CPI.STORE") == 0)
                    cfg->store_cpi = value;
                else
                    printf("Aviso: chave desconhecida '%s' no arquivo de configuracao\n", key);
            }
        }
        fclose(fp);
    }
    global_config = cfg;
}

/* Memória RAM */

double ram_load(RAM *ram, int addr)
{
    if (addr < 0 || addr >= ram->size)
    {
        printf("[RAM] Endereço inválido: %d\n", addr);
        return 0.0;
    }
    return ram->data[addr];
}

void ram_store(RAM *ram, int addr, double value)
{
    if (addr < 0 || addr >= ram->size)
    {
        printf("[RAM] Endereço inválido para store: %d\n", addr);
        return;
    }
    ram->data[addr] = value;
}

static void init_ram(int size)
{
    global_ram.size = size;
    global_ram.data = calloc(size, sizeof(double));
    global_ram.load = ram_load;
    global_ram.store = ram_store;
}

/* Parsing de instruções */

static int instruction_count = 0;

// Funçao auxiliar para parsing de offset(base)
static bool parse_offset_base(const char *str, int *offset, int *base)
{
    int rnum = 0;
    if (sscanf(str, "%d(r%d)", offset, &rnum) == 2)
    {
        *base = rnum;
        return true;
    }
    return false;
}

static int parse_instruction_line(const char *line, Instruction *out)
{
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '\0' || *line == '\n' || *line == '#')
        return 0;

    Instruction ins = {0};
    int r0, r1, r2, imm;
    char offsetBaseStr[32];
    const char *op_name = NULL;

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
    else if (sscanf(line, "load r%d,%31s", &r0, offsetBaseStr) == 2)
    {
        int offset, base;
        if (!parse_offset_base(offsetBaseStr, &offset, &base))
            return 0;
        ins.op = LOAD;
        op_name = "LOAD";
        ins.regs[0] = r0;     // destino
        ins.regs[1] = base;   // registrador base
        ins.regs[2] = offset; // imediato offset
    }
    else if (sscanf(line, "store r%d,%31s", &r0, offsetBaseStr) == 2)
    {
        int offset, base;
        if (!parse_offset_base(offsetBaseStr, &offset, &base))
            return 0;
        ins.op = STORE;
        op_name = "STORE";
        ins.regs[0] = r0;     // registrador fonte (valor)
        ins.regs[1] = base;   // registrador base (endereço)
        ins.regs[2] = offset; // imediato offset
    }
    else if (strncmp(line, "halt", 4) == 0)
    {
        ins.op = HALT;
        op_name = "HALT";
    }
    else
    {
        return 0; //! linha nao reconhecida
    }

    if (op_name)
    {
        if (ins.op == LI)
            printf("[Decode] %-4s rd=r%d imm=%d\n",
                   op_name, ins.regs[0], ins.regs[1]);
        else if (ins.op == LOAD || ins.op == STORE)
            printf("[Decode] %-5s r%d, %d(r%d)\n",
                   op_name, ins.regs[0], ins.regs[2], ins.regs[1]);
        else if (ins.op == HALT)
            printf("[Decode] HALT\n");
        else
            printf("[Decode] %-4s rd=r%d rs=r%d rt=r%d\n",
                   op_name, ins.regs[0], ins.regs[1], ins.regs[2]);
    }

    *out = ins;
    return 1;
}

/// @brief carrega as instruções do arquivo de texto `instructions.txt`
/// @return Array de `Instruction`
Instruction *pub_load_instructions(void)
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

/* RegisterFile */

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
static bool register_commit_value(RegisterFile *self, int index, Entry rob_entry, double value)
{
    if (index >= self->size)
    {
        printf("[Error][RegFile] Index %d fora do range\n", index);
        return false;
    }
    RegisterStatus *reg = &self->registers[index];
    if (reg->qi != rob_entry)
    {
        printf("Registrador nao escrito por esse ROB: entry %d != entry %d\n", reg->qi, rob_entry);
        return false;
    }
    reg->value = value;
    reg->qi = 0;
    printf("[Commit] Registrador %d atualizado com valor %f\n", index, value);
    return true;
}

/// @brief Cria o Register File ( registradores )
/// @param size quantos registradores terá o register file
/// @return ponteiro para o register file
static RegisterFile *pub_create_register_file(int size)
{
    RegisterFile *regFile = malloc(sizeof(RegisterFile));
    if (!regFile)
        PANIC("Erro em alocaçao para RegisterFile");
    regFile->size = size;
    regFile->registers = (RegisterStatus *)malloc(size * sizeof(RegisterStatus));
    if (!regFile->registers)
        PANIC("Erro em alocaçao para RegisterStatus");
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
    printf("[RegisterFile] \n");
    for (int i = 0; i < regFile->size; i++)
    {
        RegisterStatus *reg = &regFile->registers[i];
        printf("r%2d = %5.2f \n", i, reg->value);
    }
    printf("\n");
}

/* InstructionQueue */

static Instruction *queue_dispatch(InstructionQueue *self)
{
    if (self->dispatchHead >= self->size)
        return NULL;
    return &self->instructions[self->dispatchHead++];
}

static Instruction *queue_peek(InstructionQueue *self)
{
    if (self->dispatchHead >= self->size)
        return NULL;
    return &self->instructions[self->dispatchHead];
}

/// @brief  Cria a fila de instruções
/// @param size tamanho da fila de instrução
/// @param instructions ponteiro para o array de instruções
/// @return  ponteiro para a fila de instruções
static InstructionQueue *pub_create_queue(int size, Instruction *instructions)
{
    InstructionQueue *queue = malloc(sizeof *queue);
    if (!queue)
        PANIC("Erro em alocaçao para InstructionQueue");
    queue->instructions = instructions;
    queue->size = size;
    queue->dispatchHead = 0;
    queue->dispatch = queue_dispatch;
    queue->peek = queue_peek;
    return queue;
}

/* ReorderBuffer */

/// @brief  Aloca e retorna um ponteiro para o ReorderBuffer
/// @param size tamanho do reorder buffer
/// @return  ponteiro para o reorder buffer
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

/// @brief insere uma instrução no reorder buffer
/// @param rob referência para o reorder buffer
/// @param inst referência para a instrução a ser inserida
/// @param rs_tag tag da reserva station que está produzindo o valor
/// @bug se a `Entry` estiver sendo usada para ordem de commit, a fila circular pode comprometer a ordem
/// @return INDEX da entrada do reorder buffer daquela instrução
Entry pub_reorder_buffer_insert(ReorderBuffer *rob, Instruction inst, int rs_tag)
{
    if (rob->count >= rob->size)
    {
        PANIC("ROB cheio");
    }

    Entry newEntry = rob->tail;
    ReorderBufferRow *row = &rob->rows[newEntry];
    row->entry = newEntry;
    row->busy = true;
    row->inst = inst;
    row->state = ROB_ISSUE;
    if (inst.op == STORE)
    {
        row->destinationRegister = 0; // STORE não tem registrador destino
    }
    else
    {
        row->destinationRegister = inst.regs[0];
    }

    row->value = 0;
    row->rs_tag = rs_tag;
    rob->tail++;
    if (rob->tail > rob->size)
        rob->tail = 1;
    rob->count++;
    return newEntry;
}

void pub_reserve_station_free(ReserverStation *self, ReserveStationRow *row)
{
    if (row->busy)
    {
        row->busy = false;
        row->qj = 0;
        row->qk = 0;
        row->vj = 0;
        row->vk = 0;
        row->dest = 0;
        row->A = 0;
        row->op = HALT; // ou algum valor padrao inválido seguro
        self->busyLen--;
    }
}
/// @brief  Atualia estado do row do ROB para write Result
/// @param rob reorder buffer
/// @param bd  broadcast
/// @param rs reserve station
static void pub_reorder_buffer_listen_broadcast(ReorderBuffer *rob, Broadcast *bd, ReserverStation *rs)
{
    ReorderBufferRow *row = &rob->rows[bd->entry];
    if (!row->busy || row->state != ROB_EXECUTE) // se não estiver ocupado ou não estiver executando, retorna
        PANIC("Tentativa de broadcast em linha do ROB que não está ocupada ou não está executando");
    row->value = bd->value;
    row->state = ROB_WRITE_RESULT;
}

/// @brief checa se há espaço no reorder buffer
/// @param rob ponteiro para o reorder buffer
/// @return `true` se o reorder buffer estiver cheio,
///
///`false` caso contrário
static bool pub_reorder_buffer_is_full(ReorderBuffer *rob)
{
    return rob->count >= rob->size;
}

/// @brief!  Tenta fazer o commit de uma instrução do reorder buffer
/// @param rob
/// @param regFile
/// @return
static bool pub_reorder_buffer_try_commit(ReorderBuffer *rob, RegisterFile *regFile)
{
    if (rob->count == 0)
    {
        printf("[Commit] ROB vazio, nao há nada a ser commitado\n");
        return false;
    }
    ReorderBufferRow *headRow = &rob->rows[rob->head];
    if (headRow->state != ROB_WRITE_RESULT)
    {
        return false;
    }
    printf("[Commit] Tentativa de commit\n");
    if (headRow->destinationRegister != 0)
    {
        printf("[Commit] [REG-WRITE] Registrador de destino: %d\n", headRow->destinationRegister);
        regFile->commit_value(regFile, headRow->destinationRegister, headRow->entry, headRow->value);
    }
    else
    {
        // Para STORE e outras sem destino, só liberar o ROB sem commit em registrador
        printf("[Commit] Commit de instruçao sem registrador de destino\n");
    }
    headRow->busy = false;
    headRow->state = ROB_COMMIT;
    rob->head++;
    if (rob->head > rob->size)
        rob->head = 1;
    rob->count--;
    printf("[Commit] Commit de instruçao realizado com sucesso. Novo head: %d\n", rob->head);
    return true;
}

/* ReserveStation */

static ReserverStation *pub_create_reserve_station(int size)
{
    ReserverStation *station = malloc(sizeof *station);
    if (!station)
        PANIC("Erro em alocaçao para ReserveStation");
    station->size = size;
    station->busyLen = 0;
    station->rows = malloc(size * sizeof(ReserveStationRow));
    if (!station->rows)
        PANIC("Erro em alocaçao para ReserveStationRow");
    for (int i = 0; i < size; i++)
        station->rows[i].busy = false;
    return station;
}

static inline void handle_immediate(const Instruction *inst,
                                    ReserveStationRow *row)
{
    switch (inst->op)
    {
    case LI:
        row->vj = inst->regs[1];
        row->qj = 0;
        row->vk = 0;
        row->qk = 0;
        break;
    default:
        break;
    }
}

static int pub_reserve_station_add_instruction(ReserverStation *self,
                                               Instruction inst,
                                               RegisterFile *regFile,
                                               ReorderBuffer *rob,
                                               Entry rob_entry)
{
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
    ReserveStationRow *row = &self->rows[slot];
    row->busy = true;
    row->op = inst.op;
    row->dest = rob_entry;

    switch (inst.op)
    {
    case LI:
        row->vj = inst.regs[1];
        row->qj = 0;
        row->vk = 0;
        row->qk = 0;
        break;

    case LOAD:
    {
        RegisterStatus *rs = regFile->get(regFile, inst.regs[1]);
        if (rs->qi == 0)
        {
            row->vj = rs->value; // base
            row->qj = 0;
        }
        else
        {
            row->qj = rs->qi;
        }
    }
        row->A = inst.regs[2];
        row->vk = 0;
        row->qk = 0;
        break;

    case STORE:
    {
        /* --- registrador base (endereço) --- */
        RegisterStatus *base = regFile->get(regFile, inst.regs[1]);
        if (base->qi == 0)
        {
            row->vk = base->value;
            row->qk = 0;
        }
        else
        {
            row->qk = base->qi;
        }

        /* --- registrador fonte (valor a gravar) --- */
        RegisterStatus *src = regFile->get(regFile, inst.regs[0]);
        if (src->qi == 0)
        { /* valor já no RF */
            row->vj = src->value;
            row->qj = 0;
        }
        else
        {
            Entry dep = src->qi; /* produtor ainda no ROB */
            ReorderBufferRow *depRow = &rob->rows[dep];
            if (depRow->busy && depRow->state == ROB_WRITE_RESULT)
            {
                /* produtor já terminou — pegue o valor imediatamente  */
                row->vj = depRow->value;
                row->qj = 0;
            }
            else
            {
                row->qj = dep; /* aguarde broadcast    */
            }
        }

        row->A = inst.regs[2]; /* offset imediato */
    }
    break;
    default:
    {
        RegisterStatus *rs = regFile->get(regFile, inst.regs[1]);
        if (rs->qi == 0)
        {
            row->vj = rs->value;
            row->qj = 0;
        }
        else
        {
            Entry dep = rs->qi;
            ReorderBufferRow *depRow = &rob->rows[dep];
            if (depRow->busy && depRow->state == ROB_WRITE_RESULT)
            {
                row->vj = depRow->value;
                row->qj = 0;
            }
            else
            {
                row->qj = dep;
            }
        }
    }
        {
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
        }
        break;
    }

    if (inst.op != STORE)
        regFile->set_rob_entry(regFile, inst.regs[0], rob_entry);

    self->busyLen++;

    return slot;
}

/// @brief  Atualiza o valor dos operandos da linha da estação de reserva
/// @param self  ponteiro para a estação de reserva
/// @param bd  broadcast
static void pub_reserve_station_listen_broadcast(ReserverStation *self, Broadcast *bd)
{
    for (int i = 0; i < self->size; i++)
    {
        ReserveStationRow *row = &self->rows[i];
        if (row->busy)
        {
            if (row->qj == bd->entry)
            {
                row->vj = bd->value;
                row->qj = 0;
            }
            if (row->qk == bd->entry)
            {
                row->vk = bd->value;
                row->qk = 0;
            }
        }
    }
}

/// @brief Retorna todas as instruções sem dependências e prontas para execução
/// filtradas por um array de operações
/// @param self  ponteiro para a estação de reserva
/// @param ops_aceitas  array de operações aceitas
/// @param ops_count  tamanho do array de operações aceitas
/// @param out_count  referência mutavel para tamanho do array de saída
/// @return  array de ponteiros para as linhas da estação de reserva prontas
static ReserveStationRow **pub_reserve_station_get_ready_filtered(ReserverStation *self,
                                                                  Operation ops_aceitas[],
                                                                  int ops_count,
                                                                  int *out_count)
{
    int cap = self->busyLen;
    ReserveStationRow **ready = malloc(cap * sizeof(ReserveStationRow *));
    int cnt = 0;

    for (int i = 0; i < self->size; i++)
    {
        ReserveStationRow *row = &self->rows[i];
        if (row->busy && row->qj == 0 && row->qk == 0)
        {
            // Verifica se a operação está no array de ops aceitas
            bool aceita = false;
            for (int j = 0; j < ops_count; j++)
            {
                if (row->op == ops_aceitas[j])
                {
                    aceita = true;
                    break;
                }
            }

            if (aceita)
            {
                ready[cnt++] = row;
            }
        }
    }

    *out_count = cnt;

    // printf("[RS] Encontrou %d instruções prontas filtradas\n", cnt);
    // for (int i = 0; i < cnt; i++)
    // {
    //     ReserveStationRow *row = ready[i];
    //     printf("[RS] %d: %s | vj=%f vk=%f\n", row->dest, op_to_str(row->op), row->vj, row->vk);
    // }
    // puts("");

    return ready;
}

static bool pub_has_free_space(ReserverStation *self)
{
    return self->busyLen < self->size;
}

/* Unidade Funcional */

/// @brief  Verifica se há espaço no buffer de instruções da unidade funcional
/// @param self  ponteiro para a unidade funcional
/// @param op  operação a ser verificada
/// @return  `true` se houver espaço, `false` caso contrário
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
        cnt = ARTH_UF_POWER;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = MUL_UF_POWER;
        break;
    case DIV:
        buf = self->div_units;
        cnt = DIV_UF_POWER;
        break;
    case LOAD:
    case STORE:
        buf = self->load_store_units;
        cnt = LOAD_STORE_UF_POWER;
        break;
    default:
        PANIC("Operação desconhecida para UF");
        return false;
    }
    for (int i = 0; i < cnt; i++)
        if (!buf[i].active)
            return true;
    return false;
}
/// @brief  Insere uma linha na unidade funcional
/// @param self  ponteiro para a unidade funcional
/// @param row  linha da RS a ser inserida
/// @return  `true` se a inserção foi bem-sucedida, `false` caso contrário
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
        cnt = ARTH_UF_POWER;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = MUL_UF_POWER;
        break;
    case DIV:
        buf = self->div_units;
        cnt = DIV_UF_POWER;
        break;
    case LOAD:
    case STORE:
        buf = self->load_store_units;
        cnt = LOAD_STORE_UF_POWER;
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
            buf[i].rs = NULL; // vamos setar a RS depois se precisar
            return true;
        }
    }
    return false;
}
/// @brief  Retorna a `ReserveStation` correta para o tipo de operação
/// @param uf unidade funcional
/// @param op operação cuja a Reserve station queremos
/// @return referência para a ReserveStation correta
static ReserverStation *get_rs_for_op(FunctionalUnit *uf, Operation op)
{
    switch (op)
    {
    case ADD:
    case SUB:
    case LI:
        return uf->arith_rs;
    case MUL:
        return uf->mul_rs;
    case DIV:
        return uf->div_rs;
    case LOAD:
    case STORE:
        return uf->load_store_rs;
    default:
        printf("[UF] [Error] Operaçao desconhecida para RS: %s\n", op_to_str(op));
        return NULL;
    }
}

static bool uf_rs_has_free_space(FunctionalUnit *self, Operation op)
{
    ReserverStation *rs = get_rs_for_op(self, op);
    if (!rs)
        return false;
    return rs->busyLen < rs->size;
}

static Broadcast *uf_tick(FunctionalUnit *self)
{
    static Broadcast out;

    UFTask *groups[] = {self->arith_units, self->mul_units, self->div_units, self->load_store_units};
    int limits[] = {ARTH_UF_POWER, MUL_UF_POWER, DIV_UF_POWER, LOAD_STORE_UF_POWER};

    for (int g = 0; g < 4; ++g) // para cada grupo de UFs (ARITH, MUL, DIV, LOAD_STORE)
    {
        for (int i = 0; i < limits[g]; ++i) // para cada Nucleo do grupo
        {
            UFTask *t = &groups[g][i];
            if (!t->active || t->remaining == 0)
                continue; // se o nucleo não está ativo ou já terminou, pula

            t->remaining--;
            printf("[UF] Executando op=%s | vj=%f vk=%f | restante=%d\n",
                   op_to_str(t->row.op), t->row.vj, t->row.vk, t->remaining);

            if (t->remaining > 0)
                continue;

            // acabou nesse ciclo
            t->active = false;
            double res = 0.0;
            switch (t->row.op)
            {
            case ADD:
                res = t->row.vj + t->row.vk;
                break;
            case SUB:
                res = t->row.vj - t->row.vk;
                break;
            case MUL:
                res = t->row.vj * t->row.vk;
                break;
            case DIV:
                res = (t->row.vk != 0.0) ? t->row.vj / t->row.vk : 0.0;
                break;
            case LI:
                res = t->row.vj;
                break;
            case LOAD:
            {
                int addr = (int)(t->row.vj + t->row.A);
                res = ram_load(&global_ram, addr);
                printf("[LOAD] end=%d valor=%f\n", addr, res);
            }
            break;
            case STORE:
            {
                int addr = (int)(t->row.vk + t->row.A);
                ram_store(&global_ram, addr, t->row.vj);
                printf("[UF] -- [STORE] end=%d valor=%f\n", addr, t->row.vj);
                out.entry = t->row.dest;
                out.value = 0; // STORE nao gera resultado para broadcast, mas libera RS e ROB
                return &out;
            }
            break;
            default:
                break;
            }

            printf("[UF] [Broadcast] Finalizou %s | ROB=%d | Resultado=%f\n",
                   op_to_str(t->row.op), t->row.dest, res);

            out.entry = t->row.dest;
            out.value = res;
            return &out;
        }
    }
    return NULL;
}
/// @brief Cria a unidade funcional para as operações (ADD, SUB, MUL, DIV, LOAD, STORE)
/// @return  ponteiro para a unidade funcional
static FunctionalUnit *pub_create_functional_unit(void)
{
    FunctionalUnit *uf = malloc(sizeof *uf);
    if (!uf)
        PANIC("Erro ao alocar FunctionalUnit");

    memset(uf->arith_units, 0, sizeof uf->arith_units);
    memset(uf->mul_units, 0, sizeof uf->mul_units);
    memset(uf->div_units, 0, sizeof uf->div_units);
    memset(uf->load_store_units, 0, sizeof uf->load_store_units);

    // Cria RS específicos para cada UF
    uf->arith_rs = pub_create_reserve_station(ARITH_RS_ROWS);
    uf->mul_rs = pub_create_reserve_station(MUL_RS_ROWS);
    uf->div_rs = pub_create_reserve_station(DIV_RS_ROWS);
    uf->load_store_rs = pub_create_reserve_station(LOAD_STORE_RS_ROWS);

    // Associa funções
    uf->instruction_buffer_available = uf_instruction_buffer_available;
    uf->push = uf_push;
    uf->broadcast = uf_tick;
    uf->rsHasFreeSpace = uf_rs_has_free_space;

    return uf;
}

char *rob_state_to_str(ROBState state)
{
    switch (state)
    {
    case ROB_ISSUE:
        return "ISSUE";
    case ROB_EXECUTE:
        return "EXECUTE";
    case ROB_WRITE_RESULT:
        return "WRITE_RESULT";
    case ROB_COMMIT:
        return "COMMIT";
    default:
        return "UNKNOWN";
    }
}

static bool uf_is_idle(FunctionalUnit *uf)
{
    UFTask *all[] = {uf->arith_units, uf->mul_units, uf->div_units, uf->load_store_units};
    int sz[] = {ARTH_UF_POWER, MUL_UF_POWER, DIV_UF_POWER, LOAD_STORE_UF_POWER};
    for (int g = 0; g < 4; g++)
        for (int i = 0; i < sz[g]; i++)
            if (all[g][i].active)
                return false;
    return true;
}

void print_reorderbuffer(ReorderBuffer *rob)
{
    printf("[ReorderBuffer PRINT]  --------\n");
    for (int i = 1; i <= rob->size; i++)
    {
        ReorderBufferRow *row = &rob->rows[i];
        if (row->busy)
        {
            printf("Entry %2d: %s | v=%f | state=%s\n", row->entry, op_to_str(row->inst.op), row->value, rob_state_to_str(row->state));
        }
    }
    printf("\n");
}

void printReserveStation(ReserverStation *rs, char * name)
{
    printf("[ReserveStation %s]  --------\n", name);
    for (int i = 0; i < rs->size; i++)
    {
        ReserveStationRow *row = &rs->rows[i];
        if (row->busy)
        {
            printf("RS %2d: %s | vj=%f vk=%f | qj=%d qk=%d\n", i, op_to_str(row->op), row->vj, row->vk, row->qj, row->qk);
        }
    }
    printf("\n");
}

void printFunctionalUnit(FunctionalUnit *uf)
{
    printf("[FunctionalUnit PRINT]  --------\n");
    for (int i = 0; i < ARTH_UF_POWER; i++)
    {
        if (uf->arith_units[i].active)
        {
            printf("UF %2d: %s | vj=%f vk=%f | restante=%d\n", i, op_to_str(uf->arith_units[i].row.op), uf->arith_units[i].row.vj, uf->arith_units[i].row.vk, uf->arith_units[i].remaining);
        }
    }
    printf("\n");
}

/* main.c */

int main()
{
    /// Incialização
    pub_start_config();
    init_ram(1024);
    register_file = pub_create_register_file(32);
    reorder_buffer = pub_create_reorder_buffer(32);
    functional_unit = pub_create_functional_unit();

    // load/parsing de instruções
    Instruction *instructions = pub_load_instructions();
    instruction_queue = pub_create_queue(pub_get_instruction_count(), instructions);

    /// flag para cessar dispatch
    bool halt_received = false;

    /// loop principal
    while (1)
    {
        printf(">>> CLOCK %d <<<\n", GLOBAL_CLOCK);

        // ISSUE
        if (!halt_received && !pub_reorder_buffer_is_full(reorder_buffer))
        {
            Instruction *inst = instruction_queue->peek(instruction_queue);
            if (inst)
            {
                if (inst->op == HALT) // se for um halt, ativa flag e declara fim de emissão de instruções
                {
                    halt_received = true;
                    printf("[HALT] Fim da emissao.\n");
                    // Descarta o HALT da fila para nao tentar emitir na RS/ROB
                    instruction_queue->dispatch(instruction_queue);
                    continue; // não processa o halt
                }
                else
                {
                    ReserverStation *rs = get_rs_for_op(functional_unit, inst->op);
                    if (!rs)
                    {
                        PANIC("[Issue] Operaçao desconhecida para RS\n");
                    }
                    if (rs->busyLen >= rs->size)
                    {
                        printf("[Issue] Sem espaço na RS para %s\n", op_to_str(inst->op));
                        // Se não houver espaço na RS, não emite a instrução,
                    }
                    else
                    {
                        printf("[Issue] Emissao de instrucao de OP = %s\n", op_to_str(inst->op));
                        inst = instruction_queue->dispatch(instruction_queue);
                        if (inst)
                        {
                            Entry entry = pub_reorder_buffer_insert(reorder_buffer, *inst, 0);
                            int rs_tag = pub_reserve_station_add_instruction(rs, *inst, register_file, reorder_buffer, entry);
                            reorder_buffer->rows[entry].rs_tag = rs_tag;
                            printf("[Issue] RS.tag = %d, ROB.entry = %d\n", rs_tag, entry);
                        }
                    }
                }
            }
        }
        Operation arith_ops[] = {ADD, SUB, LI};
        Operation mul_ops[] = {MUL};
        Operation div_ops[] = {DIV};
        Operation load_store_ops[] = {LOAD, STORE};

        // EXECUTE - Unidade Aritmética (ADD, SUB, LI)
        // puts("EXECUTANDO UNIDADE ARITMETICA");
        for (int i = 0; i < ARTH_UF_POWER; i++)
        { // para toda unidade funcional aritmética
            UFTask *task = &functional_unit->arith_units[i];
            if (!task->active) // se a unidade não estiver ocupada
            {
                ReserverStation *rs = functional_unit->arith_rs;
                int ready_count = 0;
                ReserveStationRow **ready = pub_reserve_station_get_ready_filtered(rs, arith_ops, 3, &ready_count);
                for (int j = 0; j < ready_count; j++)
                { // para cada instrução pronta
                    if (functional_unit->instruction_buffer_available(functional_unit, ready[j]->op))
                    {
                        if (functional_unit->push(functional_unit, *ready[j])) // se a instrução da RS for efetivada na UF
                        {
                            // adiciona
                            reorder_buffer->rows[ready[j]->dest].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.destRegister = %d\n", ready[j]->dest);
                            pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                            break;                                  // só dispara 1 por ciclo por unidade
                        }
                    }
                }
                free(ready);
            }
        }

        // EXECUTE - Unidade MUL
        
        for (int i = 0; i < MUL_UF_POWER; i++)
        {
            UFTask *task = &functional_unit->mul_units[i];
            if (!task->active)
            {
                ReserverStation *rs = functional_unit->mul_rs;
                int ready_count = 0;
                ReserveStationRow **ready = pub_reserve_station_get_ready_filtered(rs, mul_ops, 1, &ready_count);
                for (int j = 0; j < ready_count; j++)
                {
                    if (functional_unit->instruction_buffer_available(functional_unit, ready[j]->op))
                    {
                        if (functional_unit->push(functional_unit, *ready[j]))
                        {
                            reorder_buffer->rows[ready[j]->dest].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.destRegister = %d\n", ready[j]->dest);
                            pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                            break;
                        }
                    }
                }
                free(ready);
            }
        }

        // EXECUTE - Unidade DIV
        //  puts("[Execute] Executando DIV");
        for (int i = 0; i < DIV_UF_POWER; i++)
        {
            UFTask *task = &functional_unit->div_units[i];
            if (!task->active)
            {
                ReserverStation *rs = functional_unit->div_rs;
                int ready_count = 0;
                ReserveStationRow **ready = pub_reserve_station_get_ready_filtered(rs, div_ops, 1, &ready_count);
                for (int j = 0; j < ready_count; j++)
                {
                    if (functional_unit->instruction_buffer_available(functional_unit, ready[j]->op))
                    {
                        if (functional_unit->push(functional_unit, *ready[j]))
                        {
                            reorder_buffer->rows[ready[j]->dest].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.destRegister = %d\n", ready[j]->dest);
                            pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                            break;
                        }
                    }
                }
                free(ready);
            }
        }

        // EXECUTE - Unidade LOAD/STORE
        // puts("[Execute] Executando LOAD/STORE");
        for (int i = 0; i < LOAD_STORE_UF_POWER; i++)
        {
            UFTask *task = &functional_unit->load_store_units[i];
            if (!task->active)
            {
                ReserverStation *rs = functional_unit->load_store_rs;
                int ready_count = 0;
                ReserveStationRow **ready = pub_reserve_station_get_ready_filtered(rs, load_store_ops, 2, &ready_count);
                for (int j = 0; j < ready_count; j++)
                {
                    if (functional_unit->instruction_buffer_available(functional_unit, ready[j]->op))
                    {
                        if (functional_unit->push(functional_unit, *ready[j]))
                        {
                            reorder_buffer->rows[ready[j]->dest].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.destRegister = %d\n", ready[j]->dest);
                            pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                            break;
                        }
                    }
                }
                free(ready);
            }
        }

        // WRITE-BACK
        Broadcast *bd = functional_unit->broadcast(functional_unit);
        if (bd)
        {
            printf("[WriteBack] ROB.entry = %d | result => %f\n", bd->entry, bd->value);
            // escuta broadcast em todas as RS dedicadas
            pub_reorder_buffer_listen_broadcast(reorder_buffer, bd, functional_unit->arith_rs);

            pub_reserve_station_listen_broadcast(functional_unit->arith_rs, bd);
            pub_reserve_station_listen_broadcast(functional_unit->mul_rs, bd);
            pub_reserve_station_listen_broadcast(functional_unit->div_rs, bd);
            pub_reserve_station_listen_broadcast(functional_unit->load_store_rs, bd);
        }

        // COMMIT
        if (pub_reorder_buffer_try_commit(reorder_buffer, register_file))
        {
            int e = reorder_buffer->head == 1 ? reorder_buffer->size : reorder_buffer->head - 1;
            printf("[Commit] in ROB entry =  %d\n", e);
        }

        if (halt_received && reorder_buffer->count == 0 &&
            functional_unit->arith_rs->busyLen == 0 &&
            functional_unit->mul_rs->busyLen == 0 &&
            functional_unit->div_rs->busyLen == 0 &&
            functional_unit->load_store_rs->busyLen == 0 &&
            uf_is_idle(functional_unit))
        {
            printf("Pipeline vazio. Ciclos: %d\n", GLOBAL_CLOCK);
            break;
        }

        GLOBAL_CLOCK++;

        if (GLOBAL_CLOCK > 20)
        {
            printRegisterFile(register_file);
            printf("Pipeline nao esvaziou em 100 ciclos. Abortando...\n");
            return 0;
        }
        print_reorderbuffer(reorder_buffer);
        printFunctionalUnit(functional_unit);
        printReserveStation(functional_unit->arith_rs, "ARITH");
        printReserveStation(functional_unit->mul_rs, "MUL");
        printReserveStation(functional_unit->div_rs, "DIV");
        printReserveStation(functional_unit->load_store_rs, "LOAD_STORE");

        puts("-----------------------------------------------------------------------------------------------------\n\n");
    }

    printRegisterFile(register_file);
    return 0;
}
