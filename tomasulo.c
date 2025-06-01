
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <locale.h>

int MUL_RS_ROWS = 2;
int DIV_RS_ROWS = 2;
int ARITH_RS_ROWS = 3;
int LOAD_STORE_RS_ROWS = 4;
int REGISTERS_LEN = 8;

/// @brief reorder buffer entry
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
    NOP,
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
    int id;
    Operation op;
    int regs[3]; // [0]=rd or src (store), [1]=rs base, [2]=rt or offset(immediate)
    int issued;  // usado para controle de issue
    int execution[2];
    int writeResult; // usado para controle de write result
    int commit;
} Instruction;

typedef struct ReserveStationRow
{
    bool busy;
    Operation op;
    double vj, vk;   // operandos
    int qj, qk;      // tags das estacões produtoras dos operandos
    Entry ROB_Entry; // entrada no ROB
    int A;           // imediato (offset para load/store)
} ReserveStationRow;

typedef struct
{
    int size;
    int busyLen;
    int head, tail;
    ReserveStationRow *rows;
} ReserverStation;

typedef struct Broadcast
{
    Entry entry;
    double value;
} Broadcast;

typedef struct InstructionQueue
{
    Instruction *instructions;
    int size;
    int dispatchHead;
    /// @brief despacha a próxima instrucao da fila `remove`
    Instruction *(*dispatch)(struct InstructionQueue *);
    /// @brief retorna referencia para a próxima instrucao a ser despachada `nao remove`
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
    UFTask *arith_units;
    UFTask *mul_units;
    UFTask *div_units;
    UFTask *load_store_units;

    // Reserve stations de cada UF
    ReserverStation *arith_rs;
    ReserverStation *mul_rs;
    ReserverStation *div_rs;
    ReserverStation *load_store_rs;

    /// @brief  Verifica se ha espaco no buffer de instrucões da unidade funcional
    /// @param self  ponteiro para a unidade funcional
    /// @param op  operacao a ser verificada
    /// @return  `true` se houver espaco, `false` caso contrario
    bool (*instruction_buffer_available)(struct FunctionalUnit *, Operation);

    /// @brief  Insere uma linha na unidade funcional
    /// @param self  ponteiro para a unidade funcional
    /// @param row  linha da RS a ser inserida
    /// @return  `true` se a insercao foi bem-sucedida, `false` caso contrario
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
    double value; /* valor a gravar em reg ou memória           */
    int mem_addr; /* ⬅ endereco efetivo se for STORE / LOAD     */
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

/* Funcões utilitarias */

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
#define CPI_DEFAULT 2

typedef enum Operation Operation;

typedef struct Config
{
    int mul_cpi;
    int add_cpi;
    int sub_cpi;
    int div_cpi;
    int load_store_cpi;
    int (*get_latency)(Operation op);
} Config;

/* Globals*/

static RAM global_ram;         // RAM global
int GLOBAL_CLOCK = 0;          // Clock global
RegisterFile *register_file;   // Registrador global
ReorderBuffer *reorder_buffer; // ROB global
// ReserverStation *reserve_station; // Removido, RS sera específico em FunctionalUnit

InstructionQueue *instruction_queue; // Fila de instrucões global
FunctionalUnit *functional_unit;     // UF global

static Config *global_config = NULL;

/* Configuracao */

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
        return global_config->add_cpi; // LI é como um ADD
    case LOAD:
    case STORE:
        return global_config->load_store_cpi;
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
    case NOP:
        return "NOP";
    default:
        return "??";
    }
}

/**
 * @brief Le as configuracões do arquivo config.txt que configura as CPI's para cada operacao
 *
 *  modifica a variavel global `global_config`
 */
void pub_start_config()
{
    FILE *fp = fopen(CONFIG_FILE, "r");
    Config *cfg = calloc(1,sizeof *cfg);
    if (!cfg)
    {
        PANIC("Erro ao alocar Config");
    }
    // valores default
    cfg->mul_cpi = CPI_DEFAULT;
    cfg->add_cpi = CPI_DEFAULT;
    cfg->sub_cpi = CPI_DEFAULT;
    cfg->div_cpi = CPI_DEFAULT;
    cfg->load_store_cpi = CPI_DEFAULT;
    cfg->get_latency = config_get_latency;

    int errors = 0;
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
            if (sscanf(line, " %35[^: ] : %d", key, &value) == 2)
            {
                if (strcmp(key, "CPI.MUL") == 0)
                {
                    cfg->mul_cpi = value;
                }
                else if (strcmp(key, "CPI.AR") == 0)
                {
                    cfg->add_cpi = cfg->sub_cpi = value;
                }
                else if (strcmp(key, "CPI.DIV") == 0)
                {
                    cfg->div_cpi = value;
                }
                else if (strcmp(key, "CPI.LOAD_STORE") == 0)
                {
                    cfg->load_store_cpi = value;
                }
                else if (strcmp(key, "MUL_BUF_LEN") == 0)
                {
                    MUL_RS_ROWS = value;
                    printf("[CONFIG] MUL_RS_ROWS set to %d\n", MUL_RS_ROWS);
                }
                else if (strcmp(key, "DIV_BUF_LEN") == 0)
                {
                    DIV_RS_ROWS = value;
                    printf("[CONFIG] DIV_RS_ROWS set to %d\n", DIV_RS_ROWS);
                }
                else if (strcmp(key, "ARITH_BUF_LEN") == 0)
                {
                    ARITH_RS_ROWS = value;
                    printf("[CONFIG] ARITH_RS_ROWS set to %d\n", ARITH_RS_ROWS);
                }
                else if (strcmp(key, "LOAD_STORE_BUF_LEN") == 0)
                {
                    LOAD_STORE_RS_ROWS = value;
                    printf("[CONFIG] LOAD_STORE_RS_ROWS set to %d\n", LOAD_STORE_RS_ROWS);
                }
                else if (strcmp(key, "REGISTERS") == 0){
                    REGISTERS_LEN = value;
                    printf("[CONFIG] REGISTERS_LEN set to %d\n", REGISTERS_LEN);
                }
                else
                {
                    printf("[CONFIG] ignorando chave desconhecida: \"%s\"\n", key);
                    errors++;
                }
            }
            else
            {
                // opcional: mostre linhas que nao bateram no sscanf
                printf("[CONFIG] ignorando linha mal formatada: \"%s\"\n", line);
            }
        }
        fclose(fp);
        puts("\n\n");
        // resumo final
        printf("[CONFIG] resultados finais:\n");
        printf("  MUL         = %d\n", cfg->mul_cpi);
        printf("  ADD         = %d\n", cfg->add_cpi);
        printf("  SUB         = %d\n", cfg->sub_cpi);
        printf("  DIV         = %d\n", cfg->div_cpi);
        printf("  LOAD_STORE  = %d\n", cfg->load_store_cpi);
        printf("  MUL_RS_ROWS = %d\n", MUL_RS_ROWS);
        printf("  DIV_RS_ROWS = %d\n", DIV_RS_ROWS);
        printf("  ARITH_RS_ROWS = %d\n", ARITH_RS_ROWS);
        printf("  LOAD_STORE_RS_ROWS = %d\n", LOAD_STORE_RS_ROWS);
        printf("  REGISTERS_LEN = %d\n", REGISTERS_LEN);
        printf("[CONFIG] Configuracoes carregada com sucesso com %d Erros\n\n", errors);
    }

    global_config = cfg;
}

/* Memória RAM */

double ram_load(RAM *ram, int addr)
{
    if (addr < 0 || addr >= ram->size)
    {
        printf("[RAM] Endereco invalido: %d\n", addr);
        return 0.0;
    }
    return ram->data[addr];
}

void ram_store(RAM *ram, int addr, double value)
{
    if (addr < 0 || addr >= ram->size)
    {
        printf("[RAM] Endereco invalido para store: %d\n", addr);
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

/* Parsing de instrucões */

static int instruction_count = 0;

// Funcao auxiliar para parsing de offset(base)
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
        ins.regs[1] = base;   // registrador base (endereco)
        ins.regs[2] = offset; // imediato offset
    }
    else if (strncmp(line, "halt", 4) == 0)
    {
        ins.op = HALT;
        op_name = "HALT";
    }
    else if (strncmp(line, "nop", 3) == 0)
    {
        ins.op = NOP;
        op_name = "NOP";
    }
    else
    {
        fprintf(stderr, "[Error] Instrucao invalida: %s\n", line);
        return 0;
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

/// @brief carrega as instrucões do arquivo de texto `instructions.txt`
/// @return Array de `Instruction`
Instruction *pub_load_instructions(void)
{
    FILE *fp = fopen(INSTRUCTIONS_FILE, "r");
    if (!fp)
        PANIC("Error opening instructions file");
    int cap = 32, n = 0;
    Instruction *arr = calloc(1,cap * sizeof(Instruction));
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
/// @param size quantos registradores tera o register file
/// @return ponteiro para o register file
static RegisterFile *pub_create_register_file(int size)
{
    RegisterFile *regFile = calloc(1,sizeof(RegisterFile));
    if (!regFile)
        PANIC("Erro em alocacao para RegisterFile");
    regFile->size = size;
    regFile->registers = (RegisterStatus *)calloc(1,size * sizeof(RegisterStatus));
    if (!regFile->registers)
        PANIC("Erro em alocacao para RegisterStatus");
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
    printf("[RegisterFile]\n");
    printf("+------+-----------+------+\n");
    printf("| Reg  |   Valor   | QI   |\n");
    printf("+------+-----------+------+\n");

    for (int i = 0; i < regFile->size; i++)
    {
        RegisterStatus *reg = &regFile->registers[i];
        printf("| r%-3d | %9.2f | %-4d |\n",
               i,
               reg->value,
               reg->qi);
    }

    printf("+------+-----------+------+\n\n");
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

/// @brief  Cria a fila de instrucões
/// @param size tamanho da fila de instrucao
/// @param instructions ponteiro para o array de instrucões
/// @return  ponteiro para a fila de instrucões
static InstructionQueue *pub_create_queue(int size, Instruction *instructions)
{
    int id = 0;
    InstructionQueue *queue = calloc(1,sizeof *queue);
    if (!queue)
        PANIC("Erro em alocacao para InstructionQueue");
    queue->instructions = instructions;
    queue->size = size;
    queue->dispatchHead = 0;
    queue->dispatch = queue_dispatch;
    queue->peek = queue_peek;
    if (size <= 0)
    {
        PANIC("Tamanho da fila de instrucões deve ser maior que zero");
    }
    if (!instructions)
    {
        PANIC("Instrucões nao podem ser nulas");
    }
    for (int i = 0; i < size; i++)
    {
        if (instructions[i].op == HALT)
            break;
        instructions[i].id = id++;
    }
    return queue;
}

/* ReorderBuffer */

/// @brief  Aloca e retorna um ponteiro para o ReorderBuffer
/// @param size tamanho do reorder buffer
/// @return  ponteiro para o reorder buffer
static ReorderBuffer *pub_create_reorder_buffer(int size)
{
    ReorderBuffer *rob = calloc(1,sizeof(ReorderBuffer));
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

/// @brief insere uma instrucao no reorder buffer
/// @param rob referência para o reorder buffer
/// @param inst referência para a instrucao a ser inserida
/// @param rs_tag tag da reserva station que esta produzindo o valor
/// @bug se a `Entry` estiver sendo usada para ordem de commit, a fila circular pode comprometer a ordem
/// @return INDEX da entrada do reorder buffer daquela instrucao
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
    row->mem_addr = -1;

    if (inst.op == STORE)
    {
        row->destinationRegister = 0; // STORE nao tem registrador destino
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
        row->ROB_Entry = 0;
        row->A = 0;
        row->op = HALT; // ou algum valor padrao invalido seguro
        self->busyLen--;
    }
}
/// @brief  Atualia estado do row do ROB para write Result
/// @param rob reorder buffer
/// @param bd  broadcast
/// @param rs reserve station
static void pub_reorder_buffer_listen_broadcast(ReorderBuffer *rob,
                                                Broadcast *bd,
                                                ReserverStation *rs)
{
    ReorderBufferRow *row = &rob->rows[bd->entry];

    // Agora aceitamos tanto EXECUTE quanto WRITE_RESULT
    if (!row->busy ||
        (row->state != ROB_EXECUTE && row->state != ROB_WRITE_RESULT))
    {
        PANIC("Tentativa de broadcast em linha do ROB que nao esta ocupada ou nao esta executando");
    }

    // Copia o valor e garante que o estado fique WRITE_RESULT
    row->value = bd->value;
    row->state = ROB_WRITE_RESULT;
}

/// @brief checa se ha espaco no reorder buffer
/// @param rob ponteiro para o reorder buffer
/// @return `true` se o reorder buffer estiver cheio,
///
///`false` caso contrario
static bool pub_reorder_buffer_is_full(ReorderBuffer *rob)
{
    return rob->count >= rob->size;
}

/**
 * @brief Tenta commitar a instrucao mais antiga do reorder buffer
 * @return `true` se conseguiu commitar, `false` se nao havia nada para commitar
 */
static bool pub_reorder_buffer_try_commit(ReorderBuffer *rob,
                                          RegisterFile *regFile,
                                          Instruction *instructions)
{
    if (rob->count == 0)
        return false;

    ReorderBufferRow *head = &rob->rows[rob->head];
    if (head->state != ROB_WRITE_RESULT)
        return false;

    int id = head->inst.id;

    /* ─── 1. garante o espaçamento de um ciclo entre WR e Commit ─── */
    if (GLOBAL_CLOCK <= instructions[id].writeResult)
        return false; /* Ainda não pode commitar */

    /* ─── 2. agora é seguro aplicar os efeitos arquiteturais ──── */
    if (head->inst.op == STORE)
    {
        ram_store(&global_ram, head->mem_addr, head->value);
        printf("[Commit][STORE] end=%d valor=%f\n",
               head->mem_addr, head->value);
    }
    else if (head->destinationRegister != 0)
    {
        regFile->commit_value(regFile,
                              head->destinationRegister,
                              head->entry,
                              head->value);
    }

    instructions[id].commit = GLOBAL_CLOCK;

    /* limpa a linha e avança o ponteiro */
    head->busy = false;
    head->state = ROB_COMMIT;
    rob->head = (rob->head % rob->size) + 1;
    rob->count--;

    return true;
}

/* ReserveStation */

static ReserverStation *pub_create_reserve_station(int size)
{
    ReserverStation *station = calloc(1,sizeof *station);
    if (!station)
        PANIC("Erro em alocacao para ReserveStation");
    station->size = size;
    station->busyLen = 0;
    station->rows = calloc(1,size * sizeof(ReserveStationRow));
    if (!station->rows)
        PANIC("Erro em alocacao para ReserveStationRow");
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
        PANIC("ReserveStation sem espaco");
    }
    ReserveStationRow *row = &self->rows[slot];
    row->busy = true;
    row->op = inst.op;
    row->ROB_Entry = rob_entry;

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
        /* --- registrador base (endereco) --- */
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
        { /* valor ja no RF */
            row->vj = src->value;
            row->qj = 0;
        }
        else
        {
            Entry dep = src->qi; /* produtor ainda no ROB */
            ReorderBufferRow *depRow = &rob->rows[dep];
            if (depRow->busy && depRow->state == ROB_WRITE_RESULT)
            {
                /* produtor ja terminou — pegue o valor imediatamente  */
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

/// @brief  Atualiza o valor dos operandos da linha da estacao de reserva
/// @param self  ponteiro para a estacao de reserva
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

/// @brief Retorna todas as instrucões sem dependências e prontas para execucao
/// filtradas por um array de operacões
/// @param self  ponteiro para a estacao de reserva
/// @param ops_aceitas  array de operacões aceitas
/// @param ops_count  tamanho do array de operacões aceitas
/// @param out_count  referência mutavel para tamanho do array de saída
/// @return  array de ponteiros para as linhas da estacao de reserva prontas
static ReserveStationRow **pub_reserve_station_get_ready_filtered(ReserverStation *self,
                                                                  Operation ops_aceitas[],
                                                                  int ops_count,
                                                                  int *out_count) // remover
{
    int cap = self->busyLen;
    ReserveStationRow **ready = calloc(1,cap * sizeof(ReserveStationRow *));
    int cnt = 0;

    for (int i = 0; i < self->size; i++)
    {
        ReserveStationRow *row = &self->rows[i];
        if (row->busy && row->qj == 0 && row->qk == 0)
        {
            // Verifica se a operacao esta no array de ops aceitas
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

    // printf("[RS] Encontrou %d instrucões prontas filtradas\n", cnt);
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

/// @brief  Verifica se ha espaco no buffer de instrucões da unidade funcional
/// @param self  ponteiro para a unidade funcional
/// @param op  operacao a ser verificada
/// @return  `true` se houver espaco, `false` caso contrario
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
        cnt = global_config->add_cpi;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = global_config->mul_cpi;
        break;
    case DIV:
        buf = self->div_units;
        cnt = global_config->div_cpi;
        break;
    case LOAD:
    case STORE:
        buf = self->load_store_units;
        cnt = global_config->load_store_cpi;
        break;
    default:
        PANIC("Operacao desconhecida para UF");
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
/// @return  `true` se a insercao foi bem-sucedida, `false` caso contrario
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
        cnt = global_config->add_cpi;
        break;
    case MUL:
        buf = self->mul_units;
        cnt = global_config->mul_cpi;
        break;
    case DIV:
        buf = self->div_units;
        cnt = global_config->div_cpi;
        break;
    case LOAD:
    case STORE:
        buf = self->load_store_units;
        cnt = global_config->load_store_cpi;
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
/// @brief  Retorna a `ReserveStation` correta para o tipo de operacao
/// @param uf unidade funcional
/// @param op operacao cuja a Reserve station queremos
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
        printf("[UF] [Error] Operacao desconhecida para RS: %s\n", op_to_str(op));
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

typedef enum
{
    NO_DEP,
    WAIT_STORE,
    FWD_READY
} StoreHazard;
/**
 * @brief  se existe STORE anterior ao LOAD que acesse o mesmo endereço.
 * @param loadEntry: Entrada do LOAD no Reorder Buffer (ROB).
 * @param addr: Endereço de memória do LOAD.
 * @param rob_out: Ponteiro opcional para armazenar a linha do ROB que causou o hazard.
 * @return:
 *   NO_DEP        → Nenhum store antes; LOAD pode prosseguir à RAM.
 *   WAIT_STORE    → Há store antes, mas ainda incompleto  → stall.
 *   FWD_READY     → Store antes, pronto, mesmo endereço   → fazer forward.
 *                   O ponteiro para a linha do ROB é devolvido em *rob_out.
 */
StoreHazard check_store_hazard(Entry loadEntry,
                               int addr,
                               ReorderBufferRow **rob_out /* opcional */)
{
    ReorderBuffer *rob = reorder_buffer;
    Entry e = rob->head;
    Entry final = rob->tail;

    /* Percorre circularmente do head até “loadEntry” (exclusive). */
    while (e != final)
    {
        ReorderBufferRow *r = &rob->rows[e];

        /* Se a linha do ROB estiver ocupada e for um STORE, verificamos end. */
        if (r->busy && r->inst.op == STORE)
        {
            /* Se ainda não calculou endereço, mem_addr == -1 → stall */
            if (r->mem_addr == -1)
            {
                return WAIT_STORE;
            }
            /* Se o endereço bate com addr do LOAD, há colisão */
            if (r->mem_addr == addr)
            {
                /* Se o STORE já está em WRITE_RESULT, devolvemos o ponteiro p/ forward */
                if (r->state == ROB_WRITE_RESULT)
                {
                    if (rob_out)
                        *rob_out = r;
                    return FWD_READY;
                }
                /* Se estiver em ISSUE ou EXECUTE, stall até ficar pronto */
                return WAIT_STORE;
            }
            /* Se r->mem_addr != addr, não é o mesmo endereço; continua a varredura */
        }

        /* Avança para a próxima posição no anel [1 .. rob->size] */
        e = (e == rob->size ? 1 : e + 1);
    }

    return NO_DEP; /* Não encontrou nenhum STORE anterior para esse endereço */
}

/// @brief  Executa 1 tick em todas as unidades funcionais
/// @param self ponteiro para a unidade funcional
/// @return um Broadcast com o resultado da execucao
static Broadcast *uf_tick(FunctionalUnit *self)
{
    static Broadcast bd_out[100];
    int len = 0;

    UFTask *groups[] = {self->arith_units,
                        self->mul_units,
                        self->div_units,
                        self->load_store_units};

    int limits[] = {global_config->add_cpi,
                    global_config->mul_cpi,
                    global_config->div_cpi,
                    global_config->load_store_cpi};

    for (int g = 0; g < 4; ++g)
    {
        for (int i = 0; i < limits[g]; ++i)
        {
            UFTask *t = &groups[g][i];
            if (!t->active) /* núcleo ocioso */
                continue;

            if (t->remaining == 1)
            {
                t->remaining--; // marca como conlcuido mas sem Broadcast
                continue;
            }
            /* 1) Avanca o clock do núcleo */
            if (t->remaining > 0)
            {
                --t->remaining;
                continue;
            }

            /* Calcula o resultado*/
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
                /* 1) Calcula endereço efetivo */
                int addr = (int)(t->row.vj + t->row.A);
                ReorderBufferRow *store_cand = NULL;
                StoreHazard sh = check_store_hazard(t->row.ROB_Entry, addr, &store_cand);

                if (sh == WAIT_STORE)
                {
                    /* Stall: não libera a unidade, nem faz broadcast */
                    continue;
                }
                else if (sh == FWD_READY)
                {
                    /* Forwarding imediato: pega o valor de store_cand->value */
                    res = store_cand->value;
                    printf("[LOAD-FWD] addr=%d  val=%f  via ROB[%d]\n",
                           addr, res, store_cand->entry);

                    /* Atualiza o próprio ROB do LOAD */
                    ReorderBufferRow *myLoadROB = &reorder_buffer->rows[t->row.ROB_Entry];
                    myLoadROB->value = res;
                    myLoadROB->state = ROB_WRITE_RESULT;
                }
                else
                {
                    /* NO_DEP: não há STORE anterior → acesso normal à RAM */
                    res = global_ram.load(&global_ram, addr);
                    printf("[LOAD]   addr=%d  val=%f  (RAM)\n", addr, res);

                    /* Atualiza o próprio ROB do LOAD */
                    ReorderBufferRow *myLoadROB = &reorder_buffer->rows[t->row.ROB_Entry];
                    myLoadROB->value = res;
                    myLoadROB->state = ROB_WRITE_RESULT;
                }

                /* Emite o broadcast do LOAD (WRITE_RESULT) */
                bd_out[len].entry = t->row.ROB_Entry;
                bd_out[len].value = res;
                len++;
                t->active = false;
                continue;
                break;
            }

            case STORE:
            {
                int addr = (int)(t->row.vk + t->row.A);
                ReorderBufferRow *storeROB = &reorder_buffer->rows[t->row.ROB_Entry];
                storeROB->mem_addr = addr;
                storeROB->value = t->row.vj;

                /* Estado do ROB do STORE deve mudar para WRITE_RESULT */
                // storeROB->state = ROB_WRITE_RESULT;

                /* broadcast “dummy” (o valor não interessa tanto,
                 *  mas libera filas de espera que chequem mem_addr) */
                bd_out[len].entry = t->row.ROB_Entry;
                bd_out[len].value = t->row.vj; /* podemos propagar só o valor */
                len++;
                t->active = false;
                continue;
                break;
            }
            default:
                break;
            }

            bd_out[len].entry = t->row.ROB_Entry;
            bd_out[len].value = res;
            t->active = false;
            len++;
        }
    }
    bd_out[len].entry = 0;

    return len > 0 ? bd_out : NULL; /* 4) Um ou nenhum broadcast */
}

/// @brief Cria a unidade funcional para as operacões (ADD, SUB, MUL, DIV, LOAD, STORE)
/// @return  ponteiro para a unidade funcional
static FunctionalUnit *pub_create_functional_unit(void)
{
    FunctionalUnit *uf = calloc(1,sizeof *uf);
    if (!uf)
        PANIC("Erro ao alocar FunctionalUnit");

    uf->arith_units = calloc(1,global_config->add_cpi * sizeof(UFTask));
    uf->mul_units = calloc(1,global_config->mul_cpi * sizeof(UFTask));
    uf->div_units = calloc(1,global_config->div_cpi * sizeof(UFTask));
    uf->load_store_units = calloc(1,global_config->load_store_cpi * sizeof(UFTask));
    // zerar
    memset(uf->arith_units, 0, global_config->add_cpi * sizeof(UFTask));
    memset(uf->mul_units, 0, global_config->mul_cpi * sizeof(UFTask));
    memset(uf->div_units, 0, global_config->div_cpi * sizeof(UFTask));
    memset(uf->load_store_units, 0, global_config->load_store_cpi * sizeof(UFTask));

    // Cria UFs

    // Cria RS específicos para cada UF
    uf->arith_rs = pub_create_reserve_station(ARITH_RS_ROWS);
    uf->mul_rs = pub_create_reserve_station(MUL_RS_ROWS);
    uf->div_rs = pub_create_reserve_station(DIV_RS_ROWS);
    uf->load_store_rs = pub_create_reserve_station(LOAD_STORE_RS_ROWS);

    // Associa funcões
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
    int sz[] = {global_config->add_cpi, global_config->mul_cpi, global_config->div_cpi, global_config->load_store_cpi};
    for (int g = 0; g < 4; g++)
        for (int i = 0; i < sz[g]; i++)
            if (all[g][i].active)
                return false;
    return true;
}

void print_Instructions_history(Instruction *instructions, int instructions_len)
{
    printf("[Instructions History] -------------------------------------------------------------\n");
    printf(" ID  | Op     |  rd  |  rs   |  rt   | Issue | Execute     | WriteResult | Commit\n");
    printf("------+-------+------+-------+-------+-------+-------------+-------------+--------\n");

    for (int i = 0; i < instructions_len; i++)
    {
        Instruction ins = instructions[i];
        if (ins.op == HALT)
            break;

        char exec_str[16];
        if (ins.execution[0] > 0 && ins.execution[1] >= ins.execution[0])
            snprintf(exec_str, sizeof(exec_str), "%3d-%-3d", ins.execution[0], ins.execution[1]);
        else
            snprintf(exec_str, sizeof(exec_str), "  -  ");

        char issue_str[16], write_str[16], commit_str[16];

        snprintf(issue_str, sizeof(issue_str), "%d", ins.issued);

        snprintf(write_str, sizeof(write_str), "%d", ins.writeResult);

        snprintf(commit_str, sizeof(commit_str), "%d", ins.commit);

        printf(
            "%4d | %-5s | r%-4d | r%-4d | r%-4d | %5s | %-11s | %11s | %6s\n",
            i,
            op_to_str(ins.op),
            ins.regs[0],
            ins.regs[1],
            ins.regs[2],
            issue_str,
            exec_str,
            write_str,
            commit_str);
    }
    printf("\n");
}

void print_reorderbuffer(ReorderBuffer *rob)
{
    printf("[ReorderBuffer PRINT] ------------------------------------------------\n");
    printf("Entry | Busy | Op    | DestReg | State        |    Value    | RS_Tag\n");
    printf("------+------|-------|---------|--------------|-------------|-------\n");
    for (int i = 1; i <= rob->size; i++)
    {
        ReorderBufferRow *row = &rob->rows[i];

        printf(
            "%5d |  %c   | %-5s | %7d | %-12s | %11.4f | %6d\n",
            row->entry,
            row->busy ? 'Y' : 'N',
            op_to_str(row->inst.op),
            row->destinationRegister,
            rob_state_to_str(row->state),
            row->value,
            row->rs_tag);
    }
    printf("\n");
}

void printReserveStation(ReserverStation *rs, const char *name)
{
    printf("[ReserveStation %s] ------------------------------------------------\n", name);
    printf("Slot | Busy | Op    |     vj     |     vk     | qj  | qk  | RobEntry |   A\n");
    printf("-----+------+-------+------------+------------+-----+-----+------+------\n");
    for (int i = 0; i < rs->size; i++)
    {
        ReserveStationRow *row = &rs->rows[i];

        printf(
            "%4d |  %c   | %-5s | %10.4f | %10.4f | %3d | %3d | %4d | %4d\n",
            i,
            row->busy ? 'Y' : 'N',
            op_to_str(row->op),
            row->vj,
            row->vk,
            row->qj,
            row->qk,
            row->ROB_Entry,
            row->A);
    }
    printf("\n");
}

void printFunctionalUnit(FunctionalUnit *uf)
{
    printf("[FunctionalUnit PRINT]  --------\n");
    for (int i = 0; i < global_config->add_cpi; i++)
    {

        printf("UF %2d: %s | vj=%f vk=%f | restante=%d\n", i, op_to_str(uf->arith_units[i].row.op), uf->arith_units[i].row.vj, uf->arith_units[i].row.vk, uf->arith_units[i].remaining);
    }

    for (int i = 0; i < global_config->mul_cpi; i++)
    {

        printf("UF %2d: %s | vj=%f vk=%f | restante=%d\n", i, op_to_str(uf->mul_units[i].row.op), uf->mul_units[i].row.vj, uf->mul_units[i].row.vk, uf->mul_units[i].remaining);
    }

    for (int i = 0; i < global_config->div_cpi; i++)
    {

        printf("UF %2d: %s | vj=%f vk=%f | restante=%d\n", i, op_to_str(uf->div_units[i].row.op), uf->div_units[i].row.vj, uf->div_units[i].row.vk, uf->div_units[i].remaining);
    }

    for (int i = 0; i < global_config->load_store_cpi; i++)
    {

        printf("UF %2d: %s | vj=%f vk=%f | restante=%d\n", i, op_to_str(uf->load_store_units[i].row.op), uf->load_store_units[i].row.vj, uf->load_store_units[i].row.vk, uf->load_store_units[i].remaining);
    }

    printf("\n");
}

/* main.c */

int main()
{
    /// Incializacao
    pub_start_config();
    init_ram(1024);
    register_file = pub_create_register_file(REGISTERS_LEN);
    reorder_buffer = pub_create_reorder_buffer(8);
    functional_unit = pub_create_functional_unit();

    // load/parsing de instrucões
    Instruction *instructions = pub_load_instructions();
    instruction_queue = pub_create_queue(pub_get_instruction_count(), instructions);

    /// flag para cessar dispatch
    bool halt_received = false;
    printf("\n\n\n[Tomasulo] Iniciando simulador\n\n\n");
    /// loop principal
    while (1)
    {
        printf(">>> CLOCK %d <<<\n", GLOBAL_CLOCK);

        Operation arith_ops[] = {ADD, SUB, LI};
        Operation mul_ops[] = {MUL};
        Operation div_ops[] = {DIV};
        Operation load_store_ops[] = {LOAD, STORE};

        // EXECUTE - Unidade Aritmetica (ADD, SUB, LI)

        for (int i = 0; i < global_config->add_cpi; i++)
        { // para toda unidade funcional aritmética
            UFTask *task = &functional_unit->arith_units[i];
            if (task->active) // se a unidade nao estiver ocupada
            {
                continue;
            }
            ReserverStation *rs = functional_unit->arith_rs;
            int ready_count = 0;
            ReserveStationRow **ready = pub_reserve_station_get_ready_filtered(rs, arith_ops, 3, &ready_count);
            for (int j = 0; j < ready_count; j++)
            { // para cada instrucao pronta
                if (functional_unit->instruction_buffer_available(functional_unit, ready[j]->op))
                {
                    if (functional_unit->push(functional_unit, *ready[j])) // se a instrucao da RS for efetivada na UF
                    {
                        // adiciona
                        reorder_buffer->rows[ready[j]->ROB_Entry].state = ROB_EXECUTE;
                        printf("[Execute] Enviado ROB.RobEntry = %d\n", ready[j]->ROB_Entry);
                        int inst_id = reorder_buffer->rows[ready[j]->ROB_Entry].inst.id;
                        instructions[inst_id].execution[0] = GLOBAL_CLOCK;
                        pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                        break;                                  // só dispara 1 por ciclo por unidade
                    }
                }
            }
            free(ready);
        }

        // EXECUTE - Unidade MUL
        for (int i = 0; i < global_config->mul_cpi; i++)
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
                            reorder_buffer->rows[ready[j]->ROB_Entry].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.Entry = %d\n", ready[j]->ROB_Entry);
                            // marca time stamp de inicio de execucao
                            int inst_id = reorder_buffer->rows[ready[j]->ROB_Entry].inst.id;
                            instructions[inst_id].execution[0] = GLOBAL_CLOCK;
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
        for (int i = 0; i < global_config->div_cpi; i++)
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
                            reorder_buffer->rows[ready[j]->ROB_Entry].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.Entry = %d\n", ready[j]->ROB_Entry);
                            int inst_id = reorder_buffer->rows[ready[j]->ROB_Entry].inst.id;
                            instructions[inst_id].execution[0] = GLOBAL_CLOCK;
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
        for (int i = 0; i < global_config->load_store_cpi; i++)
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
                            reorder_buffer->rows[ready[j]->ROB_Entry].state = ROB_EXECUTE;
                            printf("[Execute] Enviado ROB.Entry = %d\n", ready[j]->ROB_Entry);
                            int inst_id = reorder_buffer->rows[ready[j]->ROB_Entry].inst.id;
                            instructions[inst_id].execution[0] = GLOBAL_CLOCK;
                            pub_reserve_station_free(rs, ready[j]); // <---- remover da RS
                            break;
                        }
                    }
                }
                free(ready);
            }
        }

        // ISSUE
        Instruction *inst = NULL;
        if (!halt_received && !pub_reorder_buffer_is_full(reorder_buffer))
        {
            inst = instruction_queue->peek(instruction_queue);
            if (!inst || inst->op == NOP)
            {
                instruction_queue->dispatch(instruction_queue); // descarta NOP
                goto END_ISSUE;                                 // pula para o fim do ciclo de emissao
            }

            if (inst->op == HALT) // se for um halt, ativa flag e declara fim de emissao de instrucões
            {
                halt_received = true;
                printf("[HALT] Fim da emissao.\n");
                // Descarta o HALT da fila para nao tentar emitir na RS/ROB
                instruction_queue->dispatch(instruction_queue);
                goto END_ISSUE; // pula para o fim do ciclo de emissao
            }

            ReserverStation *rs = get_rs_for_op(functional_unit, inst->op);
            if (!rs)
            {
                PANIC("[Issue] Operacao desconhecida para RS\n");
            }
            if (rs->busyLen >= rs->size)
            {
                printf("[Issue] Sem espaco na RS para %s\n", op_to_str(inst->op));
                goto END_ISSUE; // pula para o fim do ciclo de emissao
                // Se nao houver espaco na RS, nao emite a instrucao,
            }

            printf("[Issue] Emissao de instrucao de OP = %s\n", op_to_str(inst->op));
            inst = instruction_queue->dispatch(instruction_queue);
            if (inst)
            {
                Entry entry = pub_reorder_buffer_insert(reorder_buffer, *inst, 0);
                int rs_tag = pub_reserve_station_add_instruction(rs, *inst, register_file, reorder_buffer, entry);
                reorder_buffer->rows[entry].rs_tag = rs_tag;
                inst->issued = GLOBAL_CLOCK; // marca o ciclo de emissao
                printf("[Issue] RS.tag = %d, ROB.entry = %d\n", rs_tag, entry);
            }
        }

    END_ISSUE:
        // WRITE-BACK
        Broadcast *bd = functional_unit->broadcast(functional_unit); // executa as UFs
        for (int i = 0; bd && bd[i].entry; i++)
        {
            {
                printf("[WriteBack] ROB.entry = %d | result => %f\n", bd[i].entry, bd[i].value);
                // escuta broadcast em todas as RS dedicadas
                pub_reorder_buffer_listen_broadcast(reorder_buffer, bd + i, functional_unit->arith_rs);

                pub_reserve_station_listen_broadcast(functional_unit->arith_rs, bd + i); //&bd[i] -> bd + i
                pub_reserve_station_listen_broadcast(functional_unit->mul_rs, bd + i);
                pub_reserve_station_listen_broadcast(functional_unit->div_rs, bd + i);
                pub_reserve_station_listen_broadcast(functional_unit->load_store_rs, bd + i);

                // timestamp
                int inst_id = reorder_buffer->rows[bd[i].entry].inst.id;
                instructions[inst_id].execution[1] = GLOBAL_CLOCK - 1; // marca o ciclo de writeback
                instructions[inst_id].writeResult = GLOBAL_CLOCK;      // marca o ciclo de write result
            }
        }

        // COMMIT
        if (pub_reorder_buffer_try_commit(reorder_buffer, register_file, instructions))
        {
            int e = reorder_buffer->head == 1 ? reorder_buffer->size : reorder_buffer->head - 1;
            printf("[Commit] in ROB entry =  %d\n", e);
        }

        if (halt_received &&
            reorder_buffer->count == 0 &&
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

        puts("\n-----------------------------------  BUFFERS ----------------------------------------------------\n\n");
        print_reorderbuffer(reorder_buffer);
        puts("");
        printFunctionalUnit(functional_unit);
        puts("");
        printReserveStation(functional_unit->arith_rs, "ARITH");
        puts("");
        printReserveStation(functional_unit->mul_rs, "MUL");
        puts("");
        printReserveStation(functional_unit->div_rs, "DIV");
        puts("");
        printReserveStation(functional_unit->load_store_rs, "LOAD_STORE");
        puts("");
        printRegisterFile(register_file);

        puts("-----------------------------------------------------------------------------------------------------\n\n");
    }

    printRegisterFile(register_file);
    puts("");
    print_Instructions_history(instructions, pub_get_instruction_count());
    puts("");
    return 0;
}
