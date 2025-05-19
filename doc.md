# Tomasulo Simulator – Documentação

> **Versão:** 1.0
> **Arquivo‑fonte:** `tomasulo_simulator.c` (monolítico)
> **Propósito:** Demonstrar, em C puro, o funcionamento do algoritmo de *Tomasulo* para execução fora‑de‑ordem e resolução dinâmica de dependências em um pipeline simples.

---

## 1. Visão Geral

O simulador implementa um pipeline de 4 estágios ‑ *Issue*, *Execute*, *Write‑back* e *Commit* – inspirado no paper original de Robert Tomasulo (1967). Ele oferece:

* **Reorder Buffer (ROB)** para manter a ordem de compromisso (precisão das exceções).
* **Estação de Reserva (RS)** que gerencia dependências e emite operações quando os operandos estão prontos.
* **Unidades Funcionais (UF)** com latências configuráveis (Add/Sub, Mul, Div).
* **Register File** com renomeação implícita via ponteiros para o ROB (campo `qi`).
* Arquivo de **configuração** (`config.txt`) que permite mudar a latência de cada UF sem recompilar.
* Arquivo de **instruções** (`instructions.txt`) em assembly resumido.

O código é dividido por comentários‑sentinela que indicam a origem de cada bloco (`/* trecho do codigo XYZ.h */`). Isso facilita split futuro em múltiplos arquivos.

---

## 2. Estrutura de Dados Principal

| Componente         | Responsabilidade                                                         | APIs Principais                                              |
| ------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------ |
| `Config`           | Guarda CPI (latência) de cada operação e expõe `get_latency()`           | `pub_start_config()`                                         |
| `InstructionQueue` | Fila de despacho em ordem de programa                                    | `dispatch()`                                                 |
| `RegisterFile`     | Registradores arquiteturais + estado de dependência (`qi`)               | `get()`, `set_rob_entry()`, `commit_value()`                 |
| `ReserverStation`  | Buffer que mantém micro‑operações até que **Qj/Qk** sejam resolvidos     | `add_instruction()`, `get_ready_all()`, `listen_broadcast()` |
| `ReorderBuffer`    | Garante *commit* in‑order; armazena valor pronto + estado                | `insert()`, `try_commit()`                                   |
| `FunctionalUnit`   | Executa instruções; cada UF é multiplexada por um pequeno buffer interno | `instruction_buffer_available()`, `push()`, `broadcast()`    |

---

## 3. Fluxo por Ciclo de Clock

1. **Issue**

   * Enquanto houver espaço na RS **e** no ROB, despacha‐se próxima instrução do `InstructionQueue`.
   * Dependências são marcadas (`Qj`, `Qk`). Para imediatos (`LI`), o operando é gravado direto em `Vj` e a RS fica livre.
2. **Execute**

   * Varre RS buscando linhas com `Qj = Qk = 0`.
   * Se a UF correspondente tiver *slot* livre, o `row` é movido para ela; o ROB passa a estado `ROB_EXECUTE`.
3. **Write‑back**

   * Quando `remaining == 0` na UF, ocorre *broadcast* (valor + `ROB.entry`).
   * RS e ROB escutam; quem dependia desse resultado atualiza‑se.
4. **Commit**

   * Se a head do ROB estiver em `ROB_WRITE_RESULT`, grava valor no `RegisterFile` (caso tenha destino) e avança o ponteiro.

Loop encerra quando `HALT` foi emitido **e** não resta trabalho em ROB, RS ou UFs.

---

## 4. Formato dos Arquivos de Entrada

### 4.1 `instructions.txt`

```
# Exemplo
li   r1,10
li   r2,20
add  r3,r1,r2
mul  r4,r3,r3
halt
```

* **Registradores:** `r0`..`r31` (32 regs).
* **Instruções:** `add`, `sub`, `mul`, `div`, `li`, `halt`.
* **Sintaxe:** vírgulas obrigatórias;

### 4.2 `config.txt`

```
# Latências em ciclos por instrução
CPI.M   : 10   # multiplicação
CPI.DIV : 20   # divisão
CPI.AR  : 5    # operações aritméticas (add/sub)
end
```

O parser carrega valores até encontrar `end`. Ausência do arquivo aciona valores padrão (`CPI_DEFAULT = 5`).

---

## 5. Compilação & Execução

1. Certifique‑se de ter `instructions.txt` (e opcionalmente `config.txt`) no mesmo diretório.
2. Execute:

   ```bash
   ./tomasulo_sim         # ou tomasulo_sim.exe
   ```
3. A saída trará logs de cada estágio, ex.:

   ```
   >>> CLOCK 0 <<<
   [Issue] Emissão de instrucao
   [Decode] LI   rd=r1 imm=10
   [Issue] RS.tag = 0, ROB.entry = 1
   ...
   [UF] [Broadcast] Finalizou ADD | ROB=3 | Resultado=30
   [Commit] Tentativa de commit
   [Commit] Registrador 3 atualizado com valor 30
   ```

