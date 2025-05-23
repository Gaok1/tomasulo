# Tomasulo Simulator

> **Versão atual:** 1.0  |  **Autor:** Luis Phillip lemos martins, João mendes, Arthur oliveira, Fernanda rodrigues dias mariano, Gabriela lacerda muniz  |  **Linguagem:** C
>
> Algoritmo de **Tomasulo** para execução fora‑de‑ordem (*out‑of‑order*) com *register renaming*, *reservation stations* e *reorder buffer* (ROB).

---

## Índice

1. [Motivação](#motivação)
2. [Visão Geral da Arquitetura](#visãogeral-da-arquitetura)
3. [Estrutura de Pastas & Arquivos](#estrutura-de-pastas--arquivos)
4. [Compilação](#compilação)
5. [Execução](#execução)
6. [Configuração (latências)](#configuração-latências)
7. [Formato das Instruções](#formato-das-instruções)
8. [Principais Estruturas de Dados](#principais-estruturas-de-dados)
9. [Ciclo de Clock](#ciclo-de-clock)
10. [Log de Saída](#log-de-saída)
11. [Limitações Conhecidas](#limitações-conhecidas)
12. [Roadmap de Melhorias](#roadmap-de-melhorias)
13. [Licença](#licença)

---

## Motivação

O pipeline superescalar contemporâneo retira paralelismo ao nível de instrução (ILP). Entretanto, **dependências (RAW, WAR, WAW)** e latências variáveis das UFs exigem lógica extra de reordenação. O algoritmo de **Tomasulo** (IBM 360/91, 1967) resolve essas questões via:

* **Renomeação de registradores** – elimina dependências *falsas* (WAR/WAW).
* **Estação de Reserva (RS)** – mantém instruções e operandos prontos.
* **Common Data Bus (CDB)** – difunde resultados imediatamente.
* **Reorder Buffer (ROB)** – garante *precise exceptions* e *commit* em ordem.

Este simulador didático demonstra esses conceitos numa implementação enxuta e comentada.

---

## Visão Geral da Arquitetura

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

* **UF Power**: `ADD/SUB/LI=2`, `MUL=1`, `DIV=1`, `LOAD/STORE=2` (configurável).
* **RS Tamanho**: ver tabela abaixo.

| UF / RS           | Linhas RS |
| ----------------- | --------- |
| Aritmética (ADD…) | 3         |
| Multiplicação     | 2         |
| Divisão           | 2         |
| Load/Store        | 4         |

---

## Estrutura de Pastas & Arquivos

| Arquivo                        | Função                                          |
| ------------------------------ | ----------------------------------------------- |
| `tomasulo.c`                   | Código fonte monolítico (≈ 2 000 linhas)        |
| `instructions.txt`             | Assembly didático a ser executado               |
| `config.txt`                   | Latência (*CPI*) por operação                   |
| `049239-tomasulo.pdf`          | Artigo base (UNICAMP 2005) – referência teórica |
| `06-pipeline-superescalar.pdf` | Slides sobre superescalaridade (PUC‑Minas)      |

> **Dica 💡**: nada impede dividir `tomasulo.c` em módulos (`rob.c`, `rs.c`, etc.). Os comentários‑sentinela `/* trecho do codigo XYZ.h */` já apontam cortes naturais.

---

## Execução

1. Ajuste `instructions.txt` e opcionalmente `config.txt`.
2. Execute:

```bash
./tomasulo_sim              # Linux/macOS
# ou
tomasulo_sim.exe            # Windows
```

O simulador imprime, ciclo a ciclo, os eventos de *Issue*, *Execute*, *Write‑back* e *Commit*.

---

## Configuração (latências)

Exemplo de `config.txt`:

```text
# Latências em ciclos por instrução (CPI)
CPI.M : 10   # multiplicação
CPI.DIV: 20  # divisão
CPI.AR : 5   # add/sub
# CPI.LOAD / CPI.STORE podem ser adicionados
end
```

Ausência do arquivo ⇒ valores **default** (todos `1`, exceto LOAD/STORE=2).

---

## Formato das Instruções

```asm
; Registradores: r0..r31 | Comentários iniciam com '#'
li   r1,10             ; imediato
add  r2,r1,r3          ; r2 = r1 + r3
mul  r4,r2,r2
load r5,16(r0)         ; r5 = MEM[r0+16]
store r5,32(r0)        ; MEM[r0+32] = r5
halt                   ; encerra emissão
```

* **Ops suportadas:** `add`, `sub`, `mul`, `div`, `li`, `load`, `store`, `halt`.
* **Sintaxe:** vírgulas obrigatórias; *offset(base)* para memória.

---

## Principais Estruturas de Dados

| Estrutura (arquivo) | Descrição rápida                         | Campos chave                   |
| ------------------- | ---------------------------------------- | ------------------------------ |
| `InstructionQueue`  | Fila FIFO de *issue*                     | `dispatchHead`, `peek()`       |
| `ReserveStationRow` | Entrada de RS                            | `op`, `vj/vk`, `qj/qk`, `dest` |
| `ReserverStation`   | Conjunto de linhas da UF                 | `size`, `busyLen`              |
| `ReorderBufferRow`  | Entrada do ROB                           | `state`, `value`, `rs_tag`     |
| `FunctionalUnit`    | Núcleo de execução + buffers             | arrays de `UFTask`             |
| `RegisterFile`      | Registradores arquiteturais + renomeação | `value`, `qi`                  |

A maior parte da lógica se encontra em três funções:

1. **`pub_reserve_station_add_instruction()`** – faz *decode* + renomeação.
2. **`uf_tick()`** – avança cada Unidade Funcional, gera *broadcast*.
3. **`pub_reorder_buffer_try_commit()`** – aplica o *commit* in‑order.

---

## Ciclo de Clock

Cada iteração do `while` principal equivale a **1 tick**:

1. **Issue** – enquanto houver espaço em RS & ROB, despacha próxima instrução.
2. **Execute** – varre RS; se operandos prontos & UF livre, inicia execução.
3. **Write‑back** – ao término, resultado é difundido no *Common Data Bus*.
4. **Commit** – head do ROB escreve no Register File (ou memória p/ `store`).

Encerramento quando:

* `halt` emitido **e**
* ROB vazio **e** RS vazias **e** todas as UFs ociosas.

---

## Log de Saída

Trecho típico (latências `ADD=1`, `MUL=2`):

```text
>>> CLOCK 0 <<<
[Issue] Emissao de instrucao de OP = ADD
[Decode] ADD  rd=r1 rs=r2 rt=r3
[Issue] RS.tag = 0, ROB.entry = 1
...
[UF] Executando op=ADD | vj=10.00 vk=20.00 | restante=0
[UF] [Broadcast] Finalizou ADD | ROB=1 | Resultado=30.00
[WriteBack] ROB.entry = 1 | result => 30.00
[Commit] Registrador 1 atualizado com valor 30.00
```

Use esse log para depurar dependências ou *deadlocks* (ver [Limitações](#limitações-conhecidas)).

---

## Limitações Conhecidas

* **ROB Entry ≠ ordem física** – fila circular pode quebrar a ordem se não gerenciada.
* **CDB único** – contende broadcast (modelo original); não simula múltiplos barramentos.
* **Sem previsão de desvio** – não há *branch speculation*.
* **Sem exceções/flush** – exceções precisas seriam tratadas no estado `ROB_EXCEPTION` (futuro).
* **Código monolítico** – didático, porém difícil de testar; modularização sugerida.

---

## Roadmap de Melhorias

* [ ] Refatorar em módulos (`rob.c`, `uf.c`, `parser.c`).
* [ ] Implementar *branch* e *speculative execution*.
* [ ] Suporte a múltiplos CDBs.
* [ ] Exportar traces para o Visual Tomasulo.
* [ ] Testes unitários com **CMocka**.
* [ ] Interface TUI utilizando **ncurses**.

---

## Licença

Código disponibilizado sob a licença **MIT**. Consulte o arquivo `LICENSE` para detalhes.
