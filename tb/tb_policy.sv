// tb_policy.sv — unit TB for tzf_policy (MICROSPEC SEC 2/3 directed cases)
`timescale 1ns/1ps
module tb_policy;
  localparam int N = 16, AW = 32;
  reg  [N-1:0]        en;
  reg  [N*AW-1:0]     base, mask;
  reg  [N*6-1:0]      perm;
  reg  [AW-1:0]       addr;
  reg  [2:0]          prot;
  reg                 wr;
  wire                grant, hit_any;
  wire [3:0]          hit_region;

  tzf_policy #(.N_REGIONS(N), .ADDR_WIDTH(AW)) dut (
    .cfg_enable(en), .cfg_base(base), .cfg_mask(mask), .cfg_perm(perm),
    .addr(addr), .axprot(prot), .is_write(wr),
    .grant(grant), .hit_any(hit_any), .hit_region(hit_region));

  // perm slice helper: region i bits {sx,sw,sr,nx,nw,nx}
  task set_perm(input int i, input [5:0] p);
    perm[i*6 +: 6] = p;
  endtask

  integer errs = 0;
  task chk(input string name, input logic exp_grant, input logic [3:0] exp_reg);
    if (grant !== exp_grant || (hit_any && hit_region !== exp_reg)) begin
      $display("FAIL %s: g=%b r=%0d exp g=%b r=%0d", name, grant, hit_region, exp_grant, exp_reg);
      errs = errs + 1;
    end else $display("pass %s", name);
  endtask

  initial begin
    en = 16'h0; base = '0; mask = '0; perm = '0;

    // T1 default-deny
    addr = 32'hC000_1000; prot = 3'b000; wr = 0;
    #1 chk("T1_default_deny", 0, 4'hF);

    // T2 secure read grant region0   perm layout {sx,sw,sr,nx,nw,nr}
    en[0]=1; base[0*AW+:AW]=32'hC000_0000; mask[0*AW+:AW]=32'hFF00_0000;
    set_perm(0, 6'b001000); // sr only
    #1 chk("T2_sec_read", 1, 4'h0);

    // T3 non-secure read same -> block
    prot = 3'b010; // ns=AxPROT[1]
    #1 chk("T3_ns_read_block", 0, 4'h0);

    // T4 instruction fetch (X) with sr-only -> block
    prot = 3'b100; wr = 0; // AxPROT[2]=fetch, secure
    #1 chk("T4_fetch_x_block", 0, 4'h0);

    // T5 fetch allowed when sx set
    set_perm(0, 6'b101000); // sx|sr
    #1 chk("T5_fetch_ok", 1, 4'h0);

    // T6 write channel uses W bit not R/X
    wr = 1; prot = 3'b000;
    #1 chk("T6_write_block_no_w", 0, 4'h0);
    set_perm(0, 6'b111000); // sw|sx|sr
    #1 chk("T7_write_ok", 1, 4'h0);

    // T8 overlap lowest-index-wins: r1 also matches, r0 must win
    en[1]=1; base[1*AW+:AW]=32'hC0F0_0000; mask[1*AW+:AW]=32'hFFF0_0000;
    set_perm(1, 6'b000001); // nr only
    addr = 32'hC0F0_1234; wr = 0; prot = 3'b000;
    #1 chk("T8_overlap_lowest", 1, 4'h0);

    // T9 disable winner -> next region takes over
    en[0]=0;
    #1 chk("T9_fallback_r1", 0, 4'h1); // nx only: secure read blocked, hit r1

    // T10 no-match code F with other region enabled elsewhere
    addr = 32'h1234_5678;
    #1 chk("T10_nomatch_F", 0, 4'hF);

    if (errs == 0) $display("TB_POLICY: ALL PASS");
    else begin $display("TB_POLICY: %0d FAILURES", errs); $fatal; end
    $finish;
  end
endmodule
