// tzf_policy.sv — combinational decision cone (MICROSPEC SEC 2/3)
// Purely combinational: this module IS the complete-mediation proof surface.
module tzf_policy #(
  parameter int N_REGIONS  = 16,
  parameter int ADDR_WIDTH = 32,
  localparam int PW = $clog2(N_REGIONS)
)(
  input  wire [N_REGIONS-1:0]             cfg_enable,
  input  wire [N_REGIONS*ADDR_WIDTH-1:0]  cfg_base,
  input  wire [N_REGIONS*ADDR_WIDTH-1:0]  cfg_mask,
  // per-region perm bits {sec_x,sec_w,sec_r, ns_x,ns_w,ns_r}
  input  wire [N_REGIONS*6-1:0]           cfg_perm,
  input  wire [ADDR_WIDTH-1:0]            addr,
  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [2:0]                       axprot,   // AxPROT[0] ignored (SEC 3)
  /* verilator lint_on UNUSEDSIGNAL */
  input  wire                             is_write,   // 1=AW channel, 0=AR
  output wire                             grant,
  output wire                             hit_any,
  output wire [PW-1:0]                    hit_region
);
  wire [N_REGIONS-1:0] hit;

  genvar g;
  generate
    for (g = 0; g < N_REGIONS; g = g + 1) begin : GEN_HIT
      assign hit[g] = cfg_enable[g] &&
        ((addr & cfg_mask[g*ADDR_WIDTH +: ADDR_WIDTH])
           == cfg_base[g*ADDR_WIDTH +: ADDR_WIDTH]);
    end
  endgenerate

  // SEC 2.1: lowest index wins on overlap
  reg [PW-1:0] prio;
  reg          any;
  integer i;
  always @* begin
    any  = 1'b0;
    prio = {PW{1'b0}};
    for (i = N_REGIONS-1; i >= 0; i = i - 1) begin
      if (hit[i]) begin
        any  = 1'b1;
        prio = i[PW-1:0];
      end
    end
  end
  assign hit_any    = any;
  assign hit_region = prio;

  // SEC 3: class = AxPROT[1]; op = W | (X iff fetch on read channel)
  /* verilator lint_off UNUSEDSIGNAL */
  wire       ns   = axprot[1];
  /* verilator lint_on UNUSEDSIGNAL */
  wire [5:0] perms = cfg_perm[prio*6 +: 6];      // {sx,sw,sr,nx,nw,nr}
  wire [2:0] sel   = ns ? perms[2:0] : perms[5:3];

  assign grant = !any ? 1'b0 :
                 is_write      ? sel[1] :
                 (axprot[2]    ? sel[2] : sel[0]);
endmodule
