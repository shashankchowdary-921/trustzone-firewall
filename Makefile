# TZFIREWALL one-command regression (msys64 make)
# Everything closes locally: zero licenses.
PY      = python
SMTBMC  = python C:/msys64/mingw64/bin/yosys-smtbmc-script.py
YOSYS   = yosys
RTL     = rtl/tzf_policy.sv rtl/tzf_faultlog.sv rtl/tzf_taint.sv rtl/tz_firewall.sv

.PHONY: all lint unit axi diff fuzz1m fm fm-ni fm-eq campaign qor clean

all: lint unit axi diff fm fm-ni fm-eq

lint:
	verilator --lint-only -Wall -Wno-DECLFILENAME --top-module tz_firewall $(RTL)

unit:
	iverilog -g2012 -o out/tb_policy.vvp tb/tb_policy.sv rtl/tzf_policy.sv
	vvp out/tb_policy.vvp

axi:
	iverilog -g2012 -o out/tb_fw.vvp tb/tb_firewall.sv $(RTL)
	vvp out/tb_fw.vvp

diff:
	$(PY) scripts/fuzz_diff.py --seeds 5 --txns 3000

fuzz1m:
	$(PY) scripts/fuzz_diff.py --seeds 25 --txns 40000 --cfg-every 2500

fm:
	$(YOSYS) -q -p "read_verilog -formal -sv $(RTL) formal/fm_mediation.sv; prep -top fm_mediation -flatten; async2sync; dffunmap; write_smt2 -wires out/fm.smt2"
	$(SMTBMC) -s z3 -t 12 out/fm.smt2
	$(SMTBMC) -s z3 -i -t 25 out/fm.smt2

fm-ni:
	$(YOSYS) -q -p "read_verilog -formal -sv $(RTL) formal/fm_nonint.sv; prep -top fm_nonint -flatten; async2sync; dffunmap; write_smt2 -wires out/ni.smt2"
	$(SMTBMC) -s z3 -t 12 out/ni.smt2
	$(SMTBMC) -s z3 -i -t 25 out/ni.smt2

fm-eq:
	$(YOSYS) -q -p "read_verilog -formal -sv $(RTL) formal/fm_equiv.sv; prep -top fm_equiv -flatten; async2sync; dffunmap; write_smt2 -wires out/eq.smt2"
	$(SMTBMC) -s z3 -t 12 out/eq.smt2
	$(SMTBMC) -s z3 -i -t 20 out/eq.smt2

campaign:
	$(PY) scripts/bug_campaign.py

qor:
	$(PY) scripts/qor_sweep.py

clean:
	rm -rf out/*.vvp out/*.smt2 out/mutants
