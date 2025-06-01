## 1. Visão Geral da Arquitetura

```text
┌────────────┐   Issue   ┌──────────────┐ Execute ┌───────────────┐ WB ┌─────────┐ Commit
│ InstrQueue │ ────────►│ Reserve St.  │────────►│ Func. Units   │───►│   ROB   │──────► RegFile
└────────────┘           └──────────────┘         └───────────────┘    └─────────┘
                            ▲  ▲  ▲  ▲                ││││               ▲       
                            │  │  │  └────── Load/Store││                │       
                            │  │  └────────── DIV      │                 │       
                            │  └───────────── MUL      ▼                 │       
                            └──────────────── ADD/SUB/LI ────────────────┘       
```

### 1.1 Visão de Alto Nível

```text
InstrQueue  --Issue-->  ReserveStation  --Execute-->  FunctionalUnits  --WB-->  ROB  --Commit-->  RegisterFile
```

* **Issue**: emite instrução da fila se houver espaço na RS e no ROB.
* **Execute**: instruções prontas entram em UF disponível.
* **Write‑Back**: resultado broadcast no CDB, atualiza ROB e RS.
* **Commit**: ROB escreve em registrador ou memória em ordem.

---

## 2. Estrutura de Pastas e Arquivos

* `tomasulo.c`              → Fonte monolítico (\~2000 linhas de C comentado).
* `instructions.txt`        → Instruções em assembly didático.
* `config.txt`              → Define latências (CPI) e tamanhos das RS.
* `README.md`               → Documentação completa (este arquivo).

---

## 3. Formato de Configuração (`config.txt`)

Se não existir, valores default:

* Latência de cada operação = 2 ciclos (LOAD/STORE = 2).
* Tamanho de RS: Aritmética=3, MUL=2, DIV=2, LOAD/STORE=4, Registradores=8.

**Sintaxe**:

```
# Latências por operação (CPI)
CPI.MUL : 10       # multiplicação em 10 ciclos
CPI.DIV : 20       # divisão em 20 ciclos
CPI.AR  : 5        # add/sub em 5 ciclos
CPI.LOAD_STORE : 5 # load/store em 5 ciclos

# Tamanho das Estações de Reserva
MUL_BUF_LEN : 2        # RS de multiplicação
DIV_BUF_LEN : 2        # RS de divisão
ARITH_BUF_LEN : 3      # RS de operações aritméticas
LOAD_STORE_BUF_LEN : 4 # RS de load/store

# Número de Registradores
REGISTERS : 8

end
```

---

## 4. Formato de Instruções (`instructions.txt`)

Cada linha contém uma instrução:

1. **R-type (add, sub, mul, div)**

   ```
   <op> r<dest>,r<src>,r<rt>
   ```

   *Exemplo*: `add r2,r1,r3`
2. **Immediate / Load**

   ```
   li r<dest>,<imediato>
   load r<dest>,<offset>(r<base>)
   ```

   *Exemplo*: `li r1,10` ou `load r5,16(r0)`
3. **Store**

   ```
   store r<src>,<offset>(r<base>)
   ```

   *Exemplo*: `store r5,32(r0)`
4. **Halt** e **NOP**

   ```
   halt
   nop
   ```

Comentários iniciados com `#` em linha única.

---

## 5. Principais Componentes e Detalhes de Implementação

### 5.1 Memória RAM

* `init_ram(size)`: aloca vetor `double data[size]`, define ponteiros `load` e `store`.
* Acesso via `global_ram.load()` e `global_ram.store()`.

### 5.2 Register File (Renomeação)

* `pub_create_register_file(int size)`: cria `RegisterFile` com array `RegisterStatus registers[size]`.
* Cada `RegisterStatus`: `{ double value; Entry qi; }`, onde `qi` aponta para entry do ROB.
* Métodos:

  * `get(regFile, idx)`: retorna `RegisterStatus *`.
  * `set_rob_entry(regFile, idx, robEntry)`: marca renomeação.
  * `commit_value(regFile, idx, robEntry, value)`: escreve valor se `qi == robEntry`.

### 5.3 Instruction Queue

* Fila simples de `Instruction *instructions` e `dispatchHead`.
* `peek()`: retorna próxima instrução sem remover.
* `dispatch()`: retorna e incrementa `dispatchHead`.
* Em `pub_create_queue(size, instructions)`, inicializa IDs sequenciais.

### 5.4 Reorder Buffer (ROB)

* `pub_create_reorder_buffer(int size)`: aloca `rows[size+1]` (1 a size), `head=tail=1`, `count=0`.
* `pub_reorder_buffer_insert(rob, inst, rs_tag)`: insere entry, configura destino, estado=ISSUE, retorna `Entry newEntry`.
* `pub_reorder_buffer_try_commit(rob, regFile, instructions)`: se head pronto (`Write_Result` e ciclo passado), faz commit:

  * Se `STORE`: grava em RAM.
  * Senão: `commit_value` no registrador.
  * Avança head, decrementa count.

### 5.5 Reserve Stations (RS)

* `pub_create_reserve_station(int size)`: aloca `ReserverStation { size, busyLen=0, rows[size] }`.
* Cada `ReserveStationRow`: `{ busy; Operation op; double vj,vk; int qj,qk; Entry ROB_Entry; int A; }`.
* `pub_reserve_station_add_instruction(rs, inst, regFile, rob, robEntry)`: adiciona instruction à RS:

  1. Encontra `freeSlot`.
  2. Configura `op`, `ROB_Entry`.
  3. Para cada tipo (LI, LOAD, STORE, aritmético): verifica operandos no regFile ou ROB:

     * Se pronto, preenche `vj/vk`; senão, coloca `qj/qk` com entry.
  4. Se `op != STORE`: chama `set_rob_entry` para dest.
  5. Incrementa `busyLen`, retorna índice.
* `pub_reserve_station_listen_broadcast(rs, bd)`: p/ cada row ocupada, se `qj == bd.entry` ou `qk == bd.entry`, atualiza `vj/vk` e zera `qj/qk`.
* `pub_reserve_station_get_ready_filtered(rs, ops_aceitas, ops_count, &out_count)`: retorna array de rows com `busy && qj==0 && qk==0` cujo `op` está em `ops_aceitas`.

### 5.6 Functional Units (UF)

* Estrutura `FunctionalUnit { UFTask *arith_units, *mul_units, *div_units, *load_store_units; ReserveStation *arith_rs, *mul_rs, *div_rs, *load_store_rs; Métodos: instruction_buffer_available, push, broadcast, rsHasFreeSpace }`.
* `UFTask`: `{ active; ReserveStationRow row; remaining; ReserveStation *rs; }`.
* `pub_create_functional_unit()`: aloca `uf`, cria arrays de `UFTask` baseados em defines (`ARITH_UF_ROWS`, etc.), e RS correspondentes.
* **Emissão para Execução**: `uf_instruction_buffer_available(uf, op)` escolhe buffer e retorna se há `!active`.
* **Inserir na UF**: `uf_push(uf, row)`: marca `UFTask.active=true`, copia row, define `remaining = latency(op)`.
* **Tick de Execução**: `uf_tick(uf)`: percorre cada UFTask:

  1. Se `remaining > 1`: decrementa.
  2. Se `remaining == 1`: decrementa (marca pronto, sem broadcast ainda).
  3. Se `remaining == 0`: calcula resultado:

     * Arith/LI: `res = vj op vk` ou `vj`.
     * **LOAD**: calcula endereço (`vj + A`), chama `check_store_hazard`:

       * `WAIT_STORE`: stalla, mantém `active=true`.
       * `FWD_READY`: recebe valor da store, atualiza ROB, gera broadcast.
       * `NO_DEP`: carrega de RAM, atualiza ROB, gera broadcast.
     * **STORE**: calcula endereço (`vk + A`), atualiza ROB (`mem_addr` e `value`), gera broadcast dummy.
     * Gera `Broadcast {entry, value}`, marca `active=false`.
* `uf_rs_has_free_space(uf, op)`: retorna se RS para `op` tem `busyLen < size`.

### 5.7 Check de Dependência Load/Store

* `check_store_hazard(loadEntry, addr, &rob_out)`: varre circularmente do `head` até `tail` no ROB:

  1. Se encontra `STORE` com `mem_addr == -1`: retorna `WAIT_STORE`.
  2. Se `mem_addr == addr && state == WRITE_RESULT`: `*rob_out = r`, retorna `FWD_READY`.
  3. Se `mem_addr == addr && state != WRITE_RESULT`: retorna `WAIT_STORE`.
* Se nada conflitante, retorna `NO_DEP`.

## 6. Pipeline Principal (Loop de Clock)

1. **Execute Aritmética (ADD, SUB, LI)**:

   * Para cada unidade aritmética livre, obtém instruções prontas em `arith_rs`; se `uf_instruction_buffer_available`, chama `uf_push`, marca `ROB.state = EXECUTE`, armazena `execution[0]`, libera RS.
2. **Execute MUL e DIV**: mesmo padrão, usando `mul_rs` e `div_rs`.
3. **Execute LOAD/STORE**: mesmo padrão, usando `load_store_rs`.
4. **Issue**:

   * Se não recebeu `HALT` e `ROB` não está cheio:

     1. `inst = instruction_queue->peek()`: se `NOP` ou sem instrução, `dispatch()` e fim.
     2. Se `inst.op == HALT`: `halt_received=true`, `dispatch()`, fim.
     3. `rs = get_rs_for_op(inst.op)`: se `rs->busyLen >= rs->size`, imprime stall e fim.
     4. Imprime `[Issue] Emissão de instrucao OP = X`, faz `dispatch()`, insere no ROB, chama `pub_reserve_station_add_instruction`, marca `inst.issued = GLOBAL_CLOCK`.
5. **Write‑Back**:

   * `bd = uf->broadcast(uf)`: array de broadcasts.
   * Para cada `bd[i]`: imprime `[WriteBack] ROB.entry = E | result => V`, chama `pub_reorder_buffer_listen_broadcast`, `pub_reserve_station_listen_broadcast` nas quatro RS, marca `instructions[id].execution[1]` e `writeResult = GLOBAL_CLOCK`.
6. **Commit**:

   * `pub_reorder_buffer_try_commit`: se head pronto, faz commit e imprime `[Commit] in ROB entry = e`.
7. **Condição de Fim**:

   * Se `halt_received && rob.count == 0 && todas RS vazias && uf_is_idle(uf)`: imprime "Pipeline vazio. Ciclos: X" e sai.
8. **Incrementa** `GLOBAL_CLOCK` e imprime estado de buffers (ROB, UFs, RS, Registradores) para depuração.

---

## 7. Documentação Resumida das Funções e Lógica de Simulação

**Objetivo Geral**: Simular a arquitetura Tomasulo destacando emissão fora de ordem, resolução de dependências dinâmica via renomeação e broadcast, e compromisso ordenado via ROB.

* **Fila de Instruções**: controla despacho, só emite se há espaço no ROB e RS.
* **Estações de Reserva (RS)**: divididas por tipo de operação; armazenam operandos (valor ou referência a ROB) e rastreamento de dependências (qj/qk).
* **Renomeação no Register File**: cada registrador guarda `qi` apontando para entry do ROB. Impede conflitos WAR/WAW.
* **Reorder Buffer (ROB)**: garante commit em ordem. Cada entry armazena instrução, destino, valor (quando pronto) e estado. Só comita quando `Write_Result` e ciclo de espera cumprido.
* **Unidades Funcionais (UF)**:para cada tipo (ADD/SUB, MUL, DIV, LOAD/STORE), com filas internas que simulam latência. Ao completar, geram evento de broadcast.
* **Broadcast (CDB Simplificado)**: resultados de UFs são broadcast a todas as RS e ao ROB, liberando dependentes.
* **Load/Store Hazards**: antes de completar load, varre o ROB atrás de stores pendentes:

  * Se store sem endereço calculado: stall.
  * Se store pronto com mesmo endereço: forwarding de valor.
  * Caso contrário, carrega de RAM.
* **Commit Ordenado**: ao comitar, store grava em memória; demais instruções escrevem em registrador se `qi` ainda corresponder. Avança head circular.
* **Contenção e Simplificações**:

  * Apenas um CDB por ciclo.
  * Cada UF despacha no máximo uma instrução por ciclo.
  * ROB com tamanho fixo (padrão 8).
  * Sem simulação de exceções ou previsão de saltos.

Esse resumo substitui descrições detalhadas de cada função, focando nos princípios de design e no fluxo do simulador.

---

## 8. Limitações Conhecidas

1. **Load & Store hazards**: atualmente o simulador implementa stalls para operação de load seguido de store, ou seja, aguarda a execução do store até que ele esteja em estado write-back no Reorder Buffer
2. **Despacho Limitado**: cada UF despacha no máximo 1 instrução por ciclo.
3. **ROB Estático**: número fixo de entradas definido no código
4. **Sem Exceções**: não trata exceções além de fluxo normal e `halt`.

---

## 9. Referências Teóricas e Artigos

1. R. Tomasulo. *An Efficient Algorithm for Exploiting Multiple Arithmetic Units*. IBM Journal, 1967.
2. *049239-tomasulo.pdf* – Artigo base (UNICAMP 2005).
3. *06-pipeline-superescalar.pdf* – Slides PUC‑Minas sobre arquitetura superescalar.

